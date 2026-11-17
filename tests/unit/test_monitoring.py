"""Phase 6 monitoring and webhook tests."""

from __future__ import annotations

import copy
import urllib.error
from pathlib import Path
from types import SimpleNamespace

from ubuntuguard.core.config import Config
from ubuntuguard.monitoring.health import evaluate_health
from ubuntuguard.monitoring.metrics import (
    Metrics,
    collect_metrics,
    compute_cpu_percent,
    disk_usages,
    fetch_text,
    node_cpu_percent,
    node_disk_usage,
    node_memory_percent,
    parse_proc_stat,
    parse_prometheus,
    read_load_per_core,
    read_memory_percent,
)
from ubuntuguard.notifications import WebhookNotifier
from ubuntuguard.reporting import build_monitoring_report, render_monitoring_text

PROMETHEUS = """\
# HELP node_cpu_seconds_total Seconds the CPUs spent in each mode.
node_cpu_seconds_total{cpu="0",mode="idle"} 100
node_cpu_seconds_total{cpu="0",mode="user"} 50
node_memory_MemTotal_bytes 1000
node_memory_MemAvailable_bytes 250
node_load1 4
node_filesystem_size_bytes{mountpoint="/"} 1000
node_filesystem_avail_bytes{mountpoint="/"} 200
"""


class _FakeResponse:
    def __init__(self, body: bytes, status: int = 200) -> None:
        self._body = body
        self.status = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class _FakeOpener:
    def __init__(self, responses: list[object]) -> None:
        self._responses = responses
        self.calls = 0

    def __call__(self, *_args: object, **_kwargs: object) -> _FakeResponse:
        self.calls += 1
        response = self._responses[min(self.calls - 1, len(self._responses) - 1)]
        if isinstance(response, Exception):
            raise response
        assert isinstance(response, _FakeResponse)
        return response


def _config_with(config: Config, section: str, values: dict[str, object]) -> Config:
    raw = copy.deepcopy(config.data)
    raw[section].update(values)
    return Config(data=raw, path=None, source="defaults")


def test_parse_proc_stat_and_cpu_percent() -> None:
    idle, total = parse_proc_stat(
        "cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 50 0 50 400 0 0 0 0 0 0\n"
    )
    assert idle == 800
    assert total == 1000
    assert compute_cpu_percent((800, 1000), (850, 1100)) == 50.0
    assert compute_cpu_percent((800, 1000), (800, 1000)) is None


def test_read_memory_and_load(tmp_path: Path) -> None:
    meminfo = tmp_path / "meminfo"
    meminfo.write_text(
        "MemTotal: 1000 kB\nMemAvailable: 250 kB\nSwapTotal: 0 kB\n",
        encoding="utf-8",
    )
    assert read_memory_percent(meminfo) == 75.0

    loadavg = tmp_path / "loadavg"
    loadavg.write_text("2.00 1.00 0.50 1/100 1234\n", encoding="utf-8")
    assert read_load_per_core(loadavg, cores=4) == 0.5

    assert read_memory_percent(tmp_path / "missing") is None
    assert read_load_per_core(tmp_path / "missing", cores=4) is None


def test_disk_usages() -> None:
    usage = SimpleNamespace(total=1000, used=400, free=600)
    result = disk_usages(("/",), usage_func=lambda _mount: usage)
    assert result == (("/", 40.0),)


def test_parse_prometheus_metrics() -> None:
    samples = parse_prometheus(PROMETHEUS)
    assert len(samples) == 7
    assert node_cpu_percent(samples) == 33.3
    assert node_memory_percent(samples) == 75.0
    assert node_disk_usage(samples, ("/",)) == (("/", 80.0),)


def test_fetch_text_uses_opener() -> None:
    opener = _FakeOpener([_FakeResponse(b"hello")])
    assert fetch_text("http://127.0.0.1:9100/metrics", opener=opener) == "hello"


def test_collect_metrics_from_node_exporter(
    config: Config, fake_executor
) -> None:
    node_config = _config_with(
        config,
        "monitoring",
        {
            "node_exporter": {
                "enabled": True,
                "url": "http://127.0.0.1:9100/metrics",
            }
        },
    )
    opener = _FakeOpener([_FakeResponse(PROMETHEUS.encode("utf-8"))])
    fake_executor.responses[("systemctl", "is-active", "ssh")] = SimpleNamespace(
        argv=("systemctl", "is-active", "ssh"),
        returncode=0,
        stdout="active\n",
        stderr="",
        timed_out=False,
        dry_run=False,
    )
    metrics = collect_metrics(node_config, fake_executor, opener=opener)

    assert metrics.source == "node_exporter"
    assert metrics.cpu_percent == 33.3
    assert metrics.memory_percent == 75.0
    assert metrics.disk_usage == (("/", 80.0),)
    assert metrics.services == (("ssh", True),)


def test_evaluate_health_and_events(tmp_path: Path, config: Config) -> None:
    metrics = Metrics(
        source="proc",
        cpu_percent=95.0,
        memory_percent=50.0,
        load_per_core=0.2,
        disk_usage=(("/", 90.0),),
        services=(("ssh", True), ("nginx", False)),
    )
    state_dir = tmp_path / "state"
    report = evaluate_health(metrics, config, state_dir)

    ids = {item.id for item in report.findings}
    assert {"HEALTH-001", "HEALTH-003", "HEALTH-005"} <= ids
    assert report.events_written == len(report.findings)
    assert (state_dir / "events.jsonl").is_file()
    statuses = {check.name: check.status for check in report.checks}
    assert statuses["cpu"] == "critical"
    assert statuses["memory"] == "ok"
    assert statuses["service:ssh"] == "ok"


def test_evaluate_health_without_metrics(config: Config) -> None:
    report = evaluate_health(Metrics(), config)
    assert report.findings == ()
    assert report.events_written == 0
    assert all(check.status == "skipped" for check in report.checks)


def test_webhook_retry_and_success() -> None:
    failure = urllib.error.URLError("connection refused")
    opener = _FakeOpener(
        [failure, failure, _FakeResponse(b"", status=204)]
    )
    notifier = WebhookNotifier(
        "http://example.invalid/hook",
        retries=2,
        retry_interval=0,
        opener=opener,
    )
    ok, detail = notifier.send({"a": 1})
    assert ok
    assert opener.calls == 3
    assert "attempt 3" in detail


def test_webhook_failure_after_retries() -> None:
    opener = _FakeOpener([urllib.error.URLError("down")])
    notifier = WebhookNotifier(
        "http://example.invalid/hook",
        retries=1,
        retry_interval=0,
        opener=opener,
    )
    ok, detail = notifier.send({"a": 1})
    assert ok is False
    assert opener.calls == 2
    assert "failed after 2 attempt" in detail


def test_webhook_without_url() -> None:
    ok, detail = WebhookNotifier("").send({})
    assert ok is False
    assert "not configured" in detail


def test_monitoring_report_rendering(config: Config) -> None:
    metrics = Metrics(
        source="proc",
        cpu_percent=91.0,
        memory_percent=40.0,
        load_per_core=0.3,
        disk_usage=(("/", 30.0),),
        services=(("ssh", True),),
    )
    report = evaluate_health(metrics, config)
    payload = build_monitoring_report(report)
    assert payload["metrics_source"] == "proc"
    assert any(item["id"] == "HEALTH-001" for item in payload["findings"])

    text = render_monitoring_text(report)
    assert "UbuntuGuard monitoring" in text
    assert "[CRITICAL] cpu" in text
    assert "HEALTH-001" in text
