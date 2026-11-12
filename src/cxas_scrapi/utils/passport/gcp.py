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

"""Google Cloud credentials and the project-number lookup of the passport.

`cxas pull --passport` reads the agent's resources through
`passport.http.ApiReader`, built with `resolve_credentials` when
`remote_fetch_allowed` permits live reads. `cxas push --passport` looks up the
target project number with `LiveGcp.project_number`, which raises `GcpError`
on failures other than "not found" (which returns None).
"""

from __future__ import annotations

import logging
import os
from typing import Any

_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
logger = logging.getLogger(__name__)


class GcpError(Exception):
    """A Google Cloud API call failed (permission denied, API disabled, ...)."""


def remote_fetch_allowed(live_introspect: bool) -> bool:
    """True when `cxas pull --passport` may call Google Cloud APIs.

    Disabled by `--no-live-introspect`, by `CXAS_PASSPORT_DISABLE_REMOTE_FETCH=1`,
    and under pytest unless `CXAS_PASSPORT_ENABLE_REMOTE_FETCH=1` (unit tests
    inject a fake reader instead).
    """
    if not live_introspect:
        return False
    if os.environ.get("CXAS_PASSPORT_DISABLE_REMOTE_FETCH") == "1":
        return False
    if os.environ.get("CXAS_PASSPORT_ENABLE_REMOTE_FETCH") == "1":
        return True
    return "PYTEST_CURRENT_TEST" not in os.environ


def _adc_credentials() -> Any:
    try:
        from google.auth import default
        from google.auth.transport.requests import Request

        creds, _ = default(scopes=[_CLOUD_PLATFORM_SCOPE])
        creds.refresh(Request())
        return creds
    except Exception as exc:  # no ADC, refresh failed, ...
        logger.debug("no application default credentials: %s", exc)
        return None


def _gcloud_access_token() -> str:
    import subprocess

    try:
        proc = subprocess.run(
            ["gcloud", "auth", "print-access-token", "--quiet"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env={**os.environ, "CLOUDSDK_CORE_DISABLE_PROMPTS": "1"},
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("no gcloud access token for live reads: %s", exc)
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def _gcloud_project_number(project_id: str) -> str | None:
    import subprocess

    try:
        proc = subprocess.run(
            [
                "gcloud",
                "projects",
                "describe",
                project_id,
                "--format=value(projectNumber)",
                "--quiet",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env={**os.environ, "CLOUDSDK_CORE_DISABLE_PROMPTS": "1"},
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("gcloud projects describe failed: %s", exc)
        return None
    out = proc.stdout.strip() if proc.returncode == 0 else ""
    return out if out.isdigit() else None


def resolve_credentials(apps_client: Any = None) -> Any:
    """Credentials for live reads: CES client, CXAS_OAUTH_TOKEN, explicit ADC, gcloud, then ADC."""
    from google.auth.credentials import Credentials as BaseCredentials

    client_creds = getattr(apps_client, "creds", None) if apps_client else None
    if client_creds is not None and (
        isinstance(client_creds, BaseCredentials)
        or isinstance(getattr(client_creds, "token", None), str)
    ):
        return client_creds

    env_token = os.environ.get("CXAS_OAUTH_TOKEN", "").strip()
    if env_token:
        from google.oauth2.credentials import Credentials

        return Credentials(token=env_token)

    if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip():
        adc = _adc_credentials()
        if adc is not None:
            return adc

    if "PYTEST_CURRENT_TEST" not in os.environ:
        token = _gcloud_access_token()
        if token:
            from google.oauth2.credentials import Credentials

            return Credentials(token=token)

    if client_creds is not None:
        return client_creds
    return _adc_credentials()


def make_live_gcp(apps_client: Any = None) -> LiveGcp | None:
    """A `LiveGcp` with the best available credentials, or None without any."""
    creds = resolve_credentials(apps_client)
    if creds is None:
        return None
    return LiveGcp(creds)


class LiveGcp:
    """Read-only Resource Manager client of `cxas push --passport`."""

    def __init__(self, creds: Any, timeout: float = 30.0) -> None:
        from google.auth.transport.requests import AuthorizedSession

        self._session = AuthorizedSession(creds)
        self._timeout = timeout

    def _get_json(self, area: str, url: str) -> dict[str, Any] | None:
        try:
            resp = self._session.request("GET", url, timeout=self._timeout)
        except Exception as exc:  # network, auth refresh, ...
            raise GcpError(f"{area}: {exc}") from exc
        if resp.status_code == 404:
            return None
        if resp.status_code >= 400:
            detail = ""
            try:
                detail = str(resp.json().get("error", {}).get("message", ""))
            except Exception:
                detail = (resp.text or "")[:200]
            raise GcpError(f"{area}: HTTP {resp.status_code} {detail}".strip())
        try:
            data = resp.json()
        except Exception as exc:
            raise GcpError(f"{area}: invalid JSON response") from exc
        return data if isinstance(data, dict) else None

    def project_number(self, project_id: str) -> str | None:
        try:
            data = self._get_json(
                "resource_manager",
                f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}",
            )
        except GcpError:
            if "PYTEST_CURRENT_TEST" not in os.environ:
                fallback = _gcloud_project_number(project_id)
                if fallback:
                    return fallback
            raise
        num = (data or {}).get("projectNumber")
        return str(num) if num else None
