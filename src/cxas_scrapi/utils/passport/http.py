# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ruff: noqa: E501, PLC0415

"""Read-only REST access to the Google Cloud APIs a passport pull reads.

`ApiReader` only sends GET requests, plus POST to `...:getIamPolicy` (Resource
Manager reads policies with POST). It never enables an API: a disabled API is
reported as `NotReadable` with category `api_disabled`. Server errors (5xx)
and rate limits (429) are retried 3 times after 1 s, 2 s and 4 s.
"""

from __future__ import annotations

import re
import time
import urllib.parse
from typing import TYPE_CHECKING, Any

from google.auth.exceptions import GoogleAuthError, TransportError

from cxas_scrapi.utils.passport.iam import redact_emails

if TYPE_CHECKING:
    from collections.abc import Callable

RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
BACKOFF_SECONDS = (1.0, 2.0, 4.0)
_PERMISSION_RE = re.compile(
    r"(?:[Pp]ermissions?\s+'?|does not have\s+)([a-z][a-zA-Z0-9]*\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+)"
)
# "... has not been used in project p before or it is disabled. Enable it by
# visiting https://console.developers.google.com/apis/api/<service>/overview"
_ENABLE_LINK_RE = re.compile(r"/apis/api/([a-z0-9.-]+\.googleapis\.com)/")


class ReadOnlyViolation(RuntimeError):
    """Code asked the reader for a call that could change the source project."""


class NotReadable(Exception):
    """A read failed for good; the resource is recorded as not readable."""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        reason: str | None = None,
        permission: str | None = None,
        service: str | None = None,
        url: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.reason = reason
        self.permission = permission
        self.service = service
        self.url = url

    @property
    def category(self) -> str:
        if self.reason == "SERVICE_DISABLED" or (
            self.status == 403 and "has not been used" in str(self)
        ):
            return "api_disabled"
        if self.status in (401, 403):
            return "permission_denied"
        if self.status == 404:
            return "not_found"
        if self.status is None or self.status in RETRY_STATUSES:
            return "unavailable"
        return "error"


def error_from_response(status: int, body: Any, url: str) -> NotReadable:
    """A NotReadable with the message, reason and permission of an API error."""
    error = body.get("error") if isinstance(body, dict) else None
    message = ""
    reason = permission = service = None
    if isinstance(error, dict):
        message = str(error.get("message") or "")
        for detail in error.get("details") or []:
            if not isinstance(detail, dict):
                continue
            reason = reason or detail.get("reason")
            meta = detail.get("metadata") or {}
            permission = permission or meta.get("permission")
            service = service or meta.get("service")
        for item in error.get("errors") or []:
            if isinstance(item, dict):
                reason = reason or item.get("reason")
    elif isinstance(body, str):
        message = body[:300]
    if not permission:
        m = _PERMISSION_RE.search(message)
        permission = m.group(1) if m else None
    if not service:
        m = _ENABLE_LINK_RE.search(message)
        service = m.group(1) if m else None
    text = redact_emails(f"HTTP {status}: {message}".strip().rstrip(":"))
    return NotReadable(
        text,
        status=status,
        reason=reason,
        permission=permission,
        service=service,
        url=url,
    )


class ApiReader:
    """GETs JSON from Google Cloud REST APIs with retries and typed errors.

    `quota_project`: some APIs (e.g. Discovery Engine) refuse end-user tokens
    without a quota project; such a call is repeated once with the
    `x-goog-user-project` header (that host then always gets it).
    """

    def __init__(
        self,
        session: Any,
        *,
        sleep: Callable[[float], None] = time.sleep,
        timeout: float = 30.0,
    ) -> None:
        self._session = session
        self._sleep = sleep
        self._timeout = timeout
        self.quota_project: str | None = None
        self._quota_hosts: set[str] = set()
        self.timings_ms: dict[str, float] = {}
        self.calls: list[tuple[str, str, int | None]] = []

    def get(self, url: str, *, area: str) -> dict[str, Any]:
        """The JSON object at `url`; raises NotReadable."""
        return self._send("GET", url, area)

    def get_bytes(self, url: str, *, area: str) -> bytes:
        """The raw bytes at `url` (e.g. `?alt=media`); raises NotReadable."""
        return self._send("GET", url, area, raw_bytes=True)

    def get_iam_policy(
        self, url: str, *, area: str, post: bool = False
    ) -> dict[str, Any]:
        """An IAM policy; `post=True` for APIs that read policies with POST."""
        if not url.split("?", 1)[0].endswith(":getIamPolicy"):
            raise ReadOnlyViolation(f"not a getIamPolicy URL: {url}")
        if not post:
            return self._send("GET", url, area)
        return self._send(
            "POST",
            url,
            area,
            body={"options": {"requestedPolicyVersion": 3}},
        )

    def _attempt(
        self,
        method: str,
        url: str,
        area: str,
        body: Any,
        raw_bytes: bool = False,
    ) -> tuple[int | None, Any]:
        """One HTTP call: (status, payload), or (None, NotReadable) on network errors."""
        host = urllib.parse.urlsplit(url).hostname or ""
        headers = (
            {"x-goog-user-project": self.quota_project}
            if self.quota_project and host in self._quota_hosts
            else None
        )
        started = time.perf_counter()
        status: int | None = None
        try:
            resp = self._session.request(
                method, url, json=body, timeout=self._timeout, headers=headers
            )
            status = resp.status_code
            if raw_bytes and status is not None and status < 400:
                return status, _bytes_of(resp)
            return status, _json_or_text(resp)
        except TransportError as exc:
            return None, NotReadable(
                f"network error: {type(exc).__name__}: {exc}", url=url
            )
        except GoogleAuthError as exc:
            status = 401
            return 401, {"error": {"message": f"authentication failed: {exc}"}}
        except OSError as exc:  # requests' ConnectionError/Timeout are OSErrors
            return None, NotReadable(
                f"network error: {type(exc).__name__}: {exc}", url=url
            )
        finally:
            self.timings_ms[area] = round(
                self.timings_ms.get(area, 0.0)
                + (time.perf_counter() - started) * 1000.0,
                3,
            )
            self.calls.append((method, url, status))

    def _send(
        self,
        method: str,
        url: str,
        area: str,
        body: Any = None,
        raw_bytes: bool = False,
    ) -> Any:
        if method != "GET" and not url.split("?", 1)[0].endswith(
            ":getIamPolicy"
        ):
            raise ReadOnlyViolation(f"{method} {url}")
        host = urllib.parse.urlsplit(url).hostname or ""
        last: NotReadable | None = None
        attempt = 0
        while attempt <= len(BACKOFF_SECONDS):
            status, payload = self._attempt(
                method, url, area, body, raw_bytes=raw_bytes
            )
            if status is None:
                last = payload
            elif status < 400:
                if raw_bytes and isinstance(payload, bytes):
                    return payload
                if not raw_bytes and isinstance(payload, dict):
                    return payload
                raise NotReadable(
                    "the API returned a response that is not a JSON object",
                    status=status,
                    url=url,
                )
            else:
                last = error_from_response(status, payload, url)
                if (
                    status == 403
                    and self.quota_project
                    and host not in self._quota_hosts
                    and "quota project" in str(last)
                ):
                    self._quota_hosts.add(host)
                    continue  # same attempt again, with the quota project
                if status not in RETRY_STATUSES:
                    raise last
            if attempt < len(BACKOFF_SECONDS):
                self._sleep(BACKOFF_SECONDS[attempt])
            attempt += 1
        if last is None:  # unreachable: every failed attempt sets `last`
            raise NotReadable("no attempt was made", url=url)
        raise NotReadable(
            f"{last} (after {len(BACKOFF_SECONDS) + 1} attempts)",
            status=last.status,
            reason=last.reason,
            permission=last.permission,
            service=last.service,
            url=url,
        )


def _bytes_of(resp: Any) -> bytes:
    content = getattr(resp, "content", None)
    if isinstance(content, (bytes, bytearray)):
        return bytes(content)
    return str(getattr(resp, "text", "") or "").encode("utf-8")


def _json_or_text(resp: Any) -> Any:
    try:
        return resp.json()
    except ValueError:
        return str(getattr(resp, "text", "") or "")


def make_reader(apps_client: Any = None) -> ApiReader | None:
    """An ApiReader with the credentials `cxas pull` uses (None without any)."""
    # Lazy: google-auth transport is only needed for live pulls.
    from google.auth.transport.requests import AuthorizedSession

    from cxas_scrapi.utils.passport.gcp import resolve_credentials

    creds = resolve_credentials(apps_client)
    if creds is None:
        return None
    return ApiReader(AuthorizedSession(creds))
