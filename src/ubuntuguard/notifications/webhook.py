"""JSON webhook notifications with retries."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any


class WebhookNotifier:
    def __init__(
        self,
        url: str,
        timeout: float = 5.0,
        retries: int = 2,
        retry_interval: float = 3.0,
        opener: Callable[..., Any] | None = None,
    ) -> None:
        self._url = url
        self._timeout = timeout
        self._retries = max(retries, 0)
        self._retry_interval = max(retry_interval, 0.0)
        self._opener = opener

    def send(self, payload: dict[str, Any]) -> tuple[bool, str]:
        if not self._url:
            return False, "webhook url not configured"

        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self._url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "ubuntuguard",
            },
            method="POST",
        )
        open_func = self._opener or urllib.request.urlopen
        attempts = self._retries + 1
        last_error = "unknown error"

        for attempt in range(1, attempts + 1):
            try:
                with open_func(request, timeout=self._timeout) as response:
                    status = int(getattr(response, "status", 200))
                if 200 <= status < 300:
                    return True, f"sent on attempt {attempt} (status {status})"
                last_error = f"unexpected status {status}"
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                last_error = str(exc)

            if attempt < attempts and self._retry_interval > 0:
                time.sleep(self._retry_interval)

        return False, f"failed after {attempts} attempt(s): {last_error}"
