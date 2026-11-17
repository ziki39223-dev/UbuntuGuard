"""Local, dependency-free web console for UbuntuGuard.

The console is intentionally small: it serves one static page and exposes a
fixed set of read-only and confirmed actions that are executed by the existing
CLI. No shell is involved and no user supplied command is ever executed.
"""

from __future__ import annotations

import difflib
import hmac
import json
import os
import platform
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

MAX_BODY = 64 * 1024
ALLOWED_ACTIONS = ("ssh", "sysctl", "firewall", "fail2ban")
_SNAPSHOT_RE = r"^[A-Za-z0-9._-]{1,128}$"
_LABEL_RE = r"^[A-Za-z0-9._-]{1,32}$"


class WebState:
    """Shared state and command runner for the web console."""

    def __init__(self, config_path: str | None = None, timeout: float = 180.0) -> None:
        self.config_path = config_path
        self.timeout = timeout
        self._lock = threading.Lock()
        self.report_path = self._choose_report_path()

    @staticmethod
    def _choose_report_path() -> Path:
        candidates = (
            Path("/var/lib/ubuntuguard/reports"),
            Path(tempfile.gettempdir()) / "ubuntuguard-web",
        )
        for directory in candidates:
            try:
                directory.mkdir(parents=True, exist_ok=True)
                probe = directory / ".write-test"
                probe.write_text("", encoding="utf-8")
                probe.unlink()
                return directory / "report.html"
            except OSError:
                continue
        return Path(tempfile.gettempdir()) / "ubuntuguard-web-report.html"

    def _base(self, as_json: bool, assume_yes: bool) -> list[str]:
        args = [sys.executable, "-m", "ubuntuguard"]
        if self.config_path:
            args.extend(["--config", self.config_path])
        if assume_yes:
            args.append("--yes")
        if as_json:
            args.append("--json")
        return args

    def run(
        self,
        command: list[str],
        *,
        as_json: bool = True,
        assume_yes: bool = False,
        timeout: float | None = None,
    ) -> dict[str, object]:
        args = self._base(as_json, assume_yes) + command
        with self._lock:
            try:
                proc = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout or self.timeout,
                    shell=False,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return {
                    "ok": False,
                    "exit_code": 124,
                    "error": "command timed out",
                    "data": None,
                    "stderr": "",
                }

        data: object | None = None
        if as_json and proc.stdout.strip():
            try:
                data = json.loads(proc.stdout)
            except json.JSONDecodeError:
                data = None

        ok = proc.returncode == 0 if not as_json else data is not None

        if as_json and data is None:
            error = proc.stderr.strip() or "command did not return JSON"
        elif not as_json:
            error = proc.stderr.strip() if not ok else ""
        else:
            error = ""

        if isinstance(data, dict) and command[:2] in (
            ["harden", "plan"],
            ["harden", "apply"],
        ):
            _add_diffs(data)

        return {
            "ok": ok,
            "exit_code": proc.returncode,
            "data": data,
            "error": error,
            "stderr": proc.stderr.strip(),
        }

    def status(self) -> dict[str, object]:
        result = self.run(["doctor"])
        data = result.get("data")
        if isinstance(data, dict):
            data["hostname"] = socket.gethostname()
            data["kernel"] = platform.release()
            data["os_pretty"] = _os_pretty()
        return result


def _add_diffs(data: dict[str, object]) -> None:
    plans = data.get("plans")
    if not isinstance(plans, list):
        return
    for plan in plans:
        if not isinstance(plan, dict):
            continue
        changes = plan.get("changes")
        if not isinstance(changes, list):
            continue
        for change in changes:
            if not isinstance(change, dict) or change.get("method") != "dropin":
                continue
            before = str(change.get("before", "")).splitlines()
            after = str(change.get("after", "")).splitlines()
            diff = list(
                difflib.unified_diff(
                    before,
                    after,
                    fromfile="current",
                    tofile="desired",
                    lineterm="",
                )
            )
            change["diff"] = "\n".join(diff) if diff else "(no content change)"


def _os_pretty() -> str:
    try:
        text = Path("/etc/os-release").read_text(encoding="utf-8")
    except OSError:
        return ""
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""


def _normalize_only(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        raw = [value]
    elif isinstance(value, list):
        raw = [str(item) for item in value]
    else:
        raise ValueError("only must be a string or a list")
    items = tuple(item.strip().lower() for item in raw if item.strip())
    unknown = [item for item in items if item not in ALLOWED_ACTIONS]
    if unknown:
        raise ValueError(f"unknown hardening action(s): {', '.join(unknown)}")
    return items


class WebHandler(BaseHTTPRequestHandler):
    server_version = "UbuntuGuardWeb/1.0"
    state: WebState
    token: str
    index_html: str

    def log_message(self, format: str, *args: object) -> None:
        if os.environ.get("UBUNTUGUARD_WEB_DEBUG"):
            super().log_message(format, *args)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            page = self.index_html.replace("__UG_TOKEN__", self.token)
            self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
            return

        if path == "/api/status":
            self._json(self.state.status())
            return

        if path == "/api/audit":
            self._json(self.state.run(["audit"]))
            return

        if path == "/api/detect":
            self._json(self.state.run(["detect"]))
            return

        if path == "/api/monitor":
            self._json(self.state.run(["monitor", "check", "--no-notify"]))
            return

        if path == "/api/backups":
            self._json(self.state.run(["backup", "list"]))
            return

        if path in ("/report/latest.html", "/api/report/latest"):
            report = self.state.report_path
            if not report.is_file():
                self._json({"ok": False, "error": "no report generated yet"}, status=404)
                return
            self._send(
                200,
                report.read_bytes(),
                "text/html; charset=utf-8",
            )
            return

        self._json({"ok": False, "error": "not found"}, status=404)

    def do_POST(self) -> None:  # noqa: N802
        if not self._token_ok():
            self._json({"ok": False, "error": "invalid web token"}, status=403)
            return

        try:
            payload = self._read_json()
        except ValueError as exc:
            self._json({"ok": False, "error": str(exc)}, status=400)
            return

        path = urlparse(self.path).path
        try:
            if path == "/api/harden/plan":
                self._json(self.state.run(self._harden_args("plan", payload)))
                return
            if path == "/api/harden/apply":
                if payload.get("confirm") != "APPLY":
                    self._json(
                        {"ok": False, "error": "type APPLY to confirm"},
                        status=400,
                    )
                    return
                self._json(
                    self.state.run(
                        self._harden_args("apply", payload),
                        assume_yes=True,
                        timeout=300,
                    )
                )
                return
            if path == "/api/backup/create":
                label = str(payload.get("label") or "web")
                if not _valid(label, _LABEL_RE):
                    self._json(
                        {"ok": False, "error": "invalid label"}, status=400
                    )
                    return
                self._json(
                    self.state.run(
                        ["backup", "create", "--label", label], timeout=300
                    )
                )
                return
            if path in ("/api/backup/verify", "/api/backup/drill"):
                snapshot_id = str(payload.get("snapshot_id") or "")
                if not _valid(snapshot_id, _SNAPSHOT_RE):
                    self._json(
                        {"ok": False, "error": "invalid snapshot id"}, status=400
                    )
                    return
                action = "verify" if path.endswith("verify") else "drill"
                self._json(
                    self.state.run(
                        ["backup", action, snapshot_id], timeout=180
                    )
                )
                return
            if path == "/api/detect/baseline":
                self._json(
                    self.state.run(["detect", "--init-baseline"], timeout=120)
                )
                return
            if path == "/api/report":
                target = self.state.report_path
                result = self.state.run(
                    ["report", "--format", "html", "--out", str(target)],
                    as_json=False,
                    timeout=300,
                )
                result["url"] = "/report/latest.html"
                result["path"] = str(target)
                self._json(result)
                return
        except ValueError as exc:
            self._json({"ok": False, "error": str(exc)}, status=400)
            return

        self._json({"ok": False, "error": "not found"}, status=404)

    def _harden_args(self, action: str, payload: dict[str, object]) -> list[str]:
        only = _normalize_only(payload.get("only"))
        args = ["harden", action]
        if action == "apply":
            args.append("--apply")
        if only:
            args.extend(["--only", ",".join(only)])
        return args

    def _token_ok(self) -> bool:
        provided = self.headers.get("X-UG-Token", "")
        return hmac.compare_digest(provided, self.token)

    def _read_json(self) -> dict[str, object]:
        raw_length = self.headers.get("Content-Length", "0") or "0"
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ValueError("invalid content length") from exc
        if length <= 0:
            return {}
        if length > MAX_BODY:
            raise ValueError("request body too large")
        raw = self.rfile.read(length)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid JSON body") from exc
        if not isinstance(parsed, dict):
            raise ValueError("JSON body must be an object")
        return parsed

    def _json(self, payload: object, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if content_type.startswith("text/html"):
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data:; "
                "style-src 'self' 'unsafe-inline'; "
                "script-src 'self' 'unsafe-inline'; connect-src 'self'; "
                "frame-ancestors 'self'; base-uri 'none'",
            )
        self.end_headers()
        self.wfile.write(body)


def _valid(value: str, pattern: str) -> bool:
    import re

    return bool(re.fullmatch(pattern, value))


def serve(host: str = "127.0.0.1", port: int = 8080, config_path: str | None = None) -> int:
    """Start the console and block until interrupted."""
    if not 1 <= port <= 65535:
        print(f"ubuntuguard web: error: invalid port {port}", file=sys.stderr)
        return 2

    index_html = Path(__file__).with_name("index.html").read_text(encoding="utf-8")
    token = secrets.token_urlsafe(24)
    state = WebState(config_path=config_path)
    handler = type(
        "BoundWebHandler",
        (WebHandler,),
        {"state": state, "token": token, "index_html": index_html},
    )

    try:
        httpd = ThreadingHTTPServer((host, port), handler)
    except OSError as exc:
        print(f"ubuntuguard web: error: {exc}", file=sys.stderr)
        return 1

    display_host = "localhost" if host in ("0.0.0.0", "::") else host
    print(f"UbuntuGuard web console: http://{display_host}:{port}")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(
            "warning: bound to a non-loopback address; the console has no "
            "authentication. Use it only on a trusted local network.",
            file=sys.stderr,
        )
    print("Press Ctrl+C to stop.", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("", file=sys.stderr)
    finally:
        httpd.server_close()
    return 0
