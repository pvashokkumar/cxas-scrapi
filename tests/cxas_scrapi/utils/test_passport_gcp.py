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

"""passport.gcp: live-read switch, credentials, and the project-number lookup of push."""

from __future__ import annotations

from typing import Any
from unittest import mock

import pytest

from cxas_scrapi.utils.passport import gcp as passport_gcp
from cxas_scrapi.utils.passport import push as passport_import
from cxas_scrapi.utils.passport.gcp import GcpError, LiveGcp

CRM_URL = "https://cloudresourcemanager.googleapis.com/v1/projects/tgt-proj"


class _Resp:
    def __init__(self, status: int, body: Any) -> None:
        self.status_code = status
        self._body = body
        self.text = body if isinstance(body, str) else ""

    def json(self) -> Any:
        if isinstance(self._body, str):
            raise ValueError("not JSON")
        return self._body


def _gcp(answer: Any) -> tuple[LiveGcp, list[tuple[str, str]]]:
    """A LiveGcp whose HTTP session answers with `answer` (a _Resp or an exception)."""
    calls: list[tuple[str, str]] = []

    def request(method: str, url: str, timeout: float) -> _Resp:
        calls.append((method, url))
        if isinstance(answer, Exception):
            raise answer
        return answer

    gcp = LiveGcp(mock.MagicMock())
    gcp._session = mock.MagicMock(request=request)
    return gcp, calls


def test_project_number_reads_resource_manager() -> None:
    gcp, calls = _gcp(_Resp(200, {"projectNumber": "999888777666"}))
    assert gcp.project_number("tgt-proj") == "999888777666"
    assert calls == [("GET", CRM_URL)]


@pytest.mark.parametrize(
    ("answer", "expected"),
    [(_Resp(404, {"error": {}}), None), (_Resp(200, {}), None)],
)
def test_project_number_not_found_or_unset_is_none(
    answer: _Resp, expected: None
) -> None:
    gcp, _ = _gcp(answer)
    assert gcp.project_number("tgt-proj") is expected


@pytest.mark.parametrize(
    ("answer", "message"),
    [
        (
            _Resp(403, {"error": {"message": "Permission denied"}}),
            "resource_manager: HTTP 403 Permission denied",
        ),
        (
            _Resp(500, "upstream reset"),
            "resource_manager: HTTP 500 upstream reset",
        ),
        (_Resp(200, "<html>"), "resource_manager: invalid JSON response"),
        (ConnectionError("network down"), "resource_manager: network down"),
    ],
)
def test_project_number_failures_raise_gcp_error(
    answer: Any, message: str
) -> None:
    gcp, _ = _gcp(answer)
    with pytest.raises(GcpError) as excinfo:
        gcp.project_number("tgt-proj")
    assert str(excinfo.value) == message


def test_remote_fetch_is_off_offline_and_under_pytest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CXAS_PASSPORT_ENABLE_REMOTE_FETCH", raising=False)
    monkeypatch.delenv("CXAS_PASSPORT_DISABLE_REMOTE_FETCH", raising=False)
    assert passport_gcp.remote_fetch_allowed(False) is False
    assert (
        passport_gcp.remote_fetch_allowed(True) is False
    )  # PYTEST_CURRENT_TEST
    monkeypatch.setenv("CXAS_PASSPORT_ENABLE_REMOTE_FETCH", "1")
    assert passport_gcp.remote_fetch_allowed(True) is True
    monkeypatch.setenv("CXAS_PASSPORT_DISABLE_REMOTE_FETCH", "1")
    assert passport_gcp.remote_fetch_allowed(True) is False


def test_resolve_credentials_prefers_the_client_then_the_env_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = mock.MagicMock()
    client.creds.token = "client-token"
    assert passport_gcp.resolve_credentials(client) is client.creds
    monkeypatch.setenv("CXAS_OAUTH_TOKEN", " env-token ")
    assert passport_gcp.resolve_credentials(None).token == "env-token"


def test_resolve_project_number_for_push(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Under pytest live reads are off: no lookup at all.
    assert passport_import.resolve_project_number("tgt-proj") is None
    monkeypatch.setenv("CXAS_PASSPORT_ENABLE_REMOTE_FETCH", "1")
    gcp, _ = _gcp(_Resp(200, {"projectNumber": "999888777666"}))
    monkeypatch.setattr(passport_gcp, "make_live_gcp", lambda _client: gcp)
    assert passport_import.resolve_project_number("tgt-proj") == "999888777666"
    failing, _ = _gcp(_Resp(403, {"error": {"message": "denied"}}))
    monkeypatch.setattr(passport_gcp, "make_live_gcp", lambda _client: failing)
    assert passport_import.resolve_project_number("tgt-proj") is None
    monkeypatch.setattr(passport_gcp, "make_live_gcp", lambda _client: None)
    assert passport_import.resolve_project_number("tgt-proj") is None
    assert passport_import.resolve_project_number(None) is None


def test_gcloud_fallbacks_disable_interactive_prompts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess  # noqa: PLC0415

    from cxas_scrapi.core import common as core_common  # noqa: PLC0415

    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.delenv("CXAS_OAUTH_TOKEN", raising=False)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    calls: list[tuple[list[str], Any, dict[str, str]]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        calls.append((cmd, kwargs.get("stdin"), kwargs.get("env") or {}))
        out = "999888777666\n" if "projects" in cmd else "cli-tok\n"
        return type("Proc", (), {"returncode": 0, "stdout": out})()

    monkeypatch.setattr(subprocess, "run", fake_run)

    # 1. passport.gcp.resolve_credentials
    creds = passport_gcp.resolve_credentials(None)
    assert creds.token == "cli-tok"

    # 2. LiveGcp.project_number fallback on HTTP 403 outside pytest
    gcp_403, _ = _gcp(_Resp(403, {"error": {"message": "denied"}}))
    assert gcp_403.project_number("tgt-proj") == "999888777666"

    # 3. Common.__init__ fallback when ADC lacks quota_project_id
    adc_no_quota = mock.MagicMock()
    adc_no_quota.quota_project_id = None
    adc_no_quota.token = "adc-tok"
    monkeypatch.setattr(
        core_common, "default", lambda scopes=None: (adc_no_quota, "p")
    )
    monkeypatch.setattr(core_common, "Request", lambda: mock.MagicMock())
    c = core_common.Common()
    assert c.token == "cli-tok"

    assert len(calls) == 3
    for cmd, stdin_arg, env_arg in calls:
        assert "--quiet" in cmd
        assert stdin_arg == subprocess.DEVNULL
        assert env_arg.get("CLOUDSDK_CORE_DISABLE_PROMPTS") == "1"


def test_explicit_service_account_and_client_creds_are_never_hijacked_by_gcloud(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess  # noqa: PLC0415

    from google.oauth2 import service_account  # noqa: PLC0415

    from cxas_scrapi.core import common as core_common  # noqa: PLC0415

    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.delenv("CXAS_OAUTH_TOKEN", raising=False)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/tmp/sa.json")

    sa_creds = mock.MagicMock(spec=service_account.Credentials)
    sa_creds.quota_project_id = None
    sa_creds.token = "sa-key-token"

    sp_mock = mock.MagicMock(
        return_value=type(
            "Proc", (), {"returncode": 0, "stdout": "hijacked-gcloud\n"}
        )()
    )
    monkeypatch.setattr(subprocess, "run", sp_mock)
    monkeypatch.setattr(
        core_common, "default", lambda scopes=None: (sa_creds, "sa-proj")
    )
    monkeypatch.setattr(core_common, "Request", lambda: mock.MagicMock())

    # Common() must keep the service account credentials and never spawn gcloud
    c = core_common.Common()
    assert c.creds is sa_creds
    assert c.token == "sa-key-token"
    sp_mock.assert_not_called()

    # resolve_credentials(client) with unrefreshed google.auth Credentials keeps client.creds
    unrefreshed_sa = mock.MagicMock(spec=service_account.Credentials)
    unrefreshed_sa.token = None
    app_client = type("Client", (), {"creds": unrefreshed_sa})()
    assert passport_gcp.resolve_credentials(app_client) is unrefreshed_sa
    sp_mock.assert_not_called()

    # resolve_credentials(None) with GOOGLE_APPLICATION_CREDENTIALS uses ADC before gcloud
    monkeypatch.setattr(
        "google.auth.default", lambda scopes=None: (sa_creds, "sa-proj")
    )
    monkeypatch.setattr(
        "google.auth.transport.requests.Request", lambda: mock.MagicMock()
    )
    assert passport_gcp.resolve_credentials(None) is sa_creds
    sp_mock.assert_not_called()


def test_project_number_production_parity_raises_on_403_and_skips_gcloud_on_404(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess  # noqa: PLC0415

    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    sp_mock = mock.MagicMock(
        return_value=type("Proc", (), {"returncode": 1, "stdout": ""})()
    )
    monkeypatch.setattr(subprocess, "run", sp_mock)

    # 404 returns None immediately without spawning gcloud
    gcp_404, _ = _gcp(_Resp(404, {"error": {}}))
    assert gcp_404.project_number("missing-proj") is None
    sp_mock.assert_not_called()

    # 403 raises GcpError when gcloud fallback also fails (parity with pytest)
    gcp_403, _ = _gcp(_Resp(403, {"error": {"message": "Permission denied"}}))
    with pytest.raises(GcpError, match="HTTP 403 Permission denied"):
        gcp_403.project_number("tgt-proj")
    sp_mock.assert_called_once()
