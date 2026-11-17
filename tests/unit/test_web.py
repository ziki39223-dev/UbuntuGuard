"""Tests for the local web console."""

from __future__ import annotations

import http.client
import threading
from http.server import ThreadingHTTPServer

import pytest

from ubuntuguard.web.server import (
    WebHandler,
    _add_diffs,
    _normalize_only,
    _valid,
)


class FakeState:
    def status(self) -> dict[str, object]:
        return {"ok": True, "data": {"version": "test"}}

    def run(
        self,
        command: list[str],
        *,
        as_json: bool = True,
        assume_yes: bool = False,
        timeout: float | None = None,
    ) -> dict[str, object]:
        return {"ok": True, "exit_code": 0, "data": {"command": command}, "error": ""}


@pytest.fixture()
def web_server():
    handler = type(
        "TestWebHandler",
        (WebHandler,),
        {"state": FakeState(), "token": "test-token", "index_html": "<html>ok</html>"},
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _request(
    port: int,
    method: str,
    path: str,
    body: bytes | None = None,
    token: str | None = None,
):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {}
    if token:
        headers["X-UG-Token"] = token
    if body is not None:
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=body, headers=headers)
    response = conn.getresponse()
    payload = response.read()
    result = (response.status, payload, dict(response.getheaders()))
    conn.close()
    return result


def test_status_uses_injected_token(web_server: int) -> None:
    status, body, _ = _request(web_server, "GET", "/api/status")
    assert status == 200
    assert b'"version": "test"' in body


def test_index_contains_injected_token(web_server: int) -> None:
    status, body, headers = _request(web_server, "GET", "/")
    assert status == 200
    assert body == b"<html>ok</html>"
    assert "Content-Security-Policy" in headers


def test_index_has_theme_and_language_controls() -> None:
    from pathlib import Path

    import ubuntuguard.web.server as server_module

    html = Path(server_module.__file__).with_name("index.html").read_text(encoding="utf-8")
    assert 'id="themeBtn"' in html
    assert 'id="langBtn"' in html
    assert "function applyI18n" in html
    assert 'data-theme="light"' in html


def test_post_requires_token(web_server: int) -> None:
    status, body, _ = _request(
        web_server, "POST", "/api/harden/plan", body=b"{}"
    )
    assert status == 403
    assert b"invalid web token" in body


def test_post_harden_plan_with_token(web_server: int) -> None:
    status, body, _ = _request(
        web_server,
        "POST",
        "/api/harden/plan",
        body=b'{"only": ["ssh", "sysctl"]}',
        token="test-token",
    )
    assert status == 200
    assert b"harden" in body


def test_apply_requires_explicit_confirmation(web_server: int) -> None:
    status, body, _ = _request(
        web_server,
        "POST",
        "/api/harden/apply",
        body=b'{"only": ["ssh"]}',
        token="test-token",
    )
    assert status == 400
    assert b"type APPLY to confirm" in body


def test_normalize_only() -> None:
    assert _normalize_only(None) == ()
    assert _normalize_only(["ssh", " sysctl "]) == ("ssh", "sysctl")
    assert _normalize_only("firewall") == ("firewall",)
    with pytest.raises(ValueError):
        _normalize_only(["ssh", "reboot"])


def test_add_diffs_for_dropin_changes() -> None:
    payload = {
        "plans": [
            {
                "action": "ssh",
                "changes": [
                    {
                        "method": "dropin",
                        "before": "",
                        "after": "PasswordAuthentication no\n",
                    }
                ],
            }
        ]
    }
    _add_diffs(payload)
    diff = payload["plans"][0]["changes"][0]["diff"]
    assert "+PasswordAuthentication no" in diff


def test_snapshot_id_validation() -> None:
    pattern = r"^[A-Za-z0-9._-]{1,128}$"
    assert _valid("20261117T074341Z-backup", pattern)
    assert not _valid("../etc/passwd", pattern)
    assert not _valid("", pattern)
