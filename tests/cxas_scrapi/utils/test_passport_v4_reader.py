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

"""ApiReader: read-only REST calls, retries, typed errors (passport layout v4)."""

from __future__ import annotations

from typing import Any

import pytest
from google.auth.exceptions import RefreshError, TransportError
from passport_v4_cloud import FakeCloud
from passport_v4_resources import UNAVAILABLE, error, permission_denied

from cxas_scrapi.utils.passport.http import (
    ApiReader,
    NotReadable,
    ReadOnlyViolation,
)

URL = "https://bigquery.googleapis.com/bigquery/v2/projects/p-1/datasets/d"


def _reader(routes: dict) -> tuple[ApiReader, FakeCloud, list[float]]:
    cloud = FakeCloud(routes)
    sleeps: list[float] = []
    return ApiReader(cloud, sleep=sleeps.append), cloud, sleeps


def test_reader_refuses_anything_but_reads() -> None:
    reader, cloud, _ = _reader({})
    with pytest.raises(ReadOnlyViolation):
        reader._send("POST", URL, "bigquery")
    with pytest.raises(ReadOnlyViolation):
        reader._send("DELETE", URL, "bigquery")
    with pytest.raises(ReadOnlyViolation):
        reader.get_iam_policy(URL, area="bigquery", post=True)
    with pytest.raises(ReadOnlyViolation):
        reader.get_iam_policy(f"{URL}:setIamPolicy", area="bigquery", post=True)
    assert cloud.requests == []


def test_reader_posts_only_to_get_iam_policy() -> None:
    url = "https://cloudresourcemanager.googleapis.com/v1/projects/p-1:getIamPolicy"
    reader, cloud, _ = _reader({("POST", url): (200, {"bindings": []})})
    assert reader.get_iam_policy(url, area="project.iam", post=True) == {
        "bindings": []
    }
    assert [(m, u) for m, u, _ in cloud.requests] == [("POST", url)]
    assert reader.calls == [("POST", url, 200)]


def test_rate_limits_and_server_errors_are_retried() -> None:
    reader, _, sleeps = _reader(
        {
            ("GET", URL): [
                error(429, "Quota exceeded."),
                UNAVAILABLE,
                (200, {"id": "d"}),
            ]
        }
    )
    assert reader.get(URL, area="bigquery") == {"id": "d"}
    assert sleeps == [1.0, 2.0]


def test_client_errors_are_not_retried() -> None:
    reader, cloud, sleeps = _reader({("GET", URL): error(404, "Not found: d")})
    with pytest.raises(NotReadable) as excinfo:
        reader.get(URL, area="bigquery")
    assert excinfo.value.category == "not_found"
    assert len(cloud.requests) == 1
    assert sleeps == []


class _Unreachable:
    """A session whose every request fails at the network level."""

    def __init__(self) -> None:
        self.attempts = 0

    def request(self, *_args: Any, **_kwargs: Any) -> Any:
        self.attempts += 1
        raise ConnectionError("connection reset")


def test_network_errors_are_retried_then_reported_unavailable() -> None:
    session = _Unreachable()
    sleeps: list[float] = []
    reader = ApiReader(session, sleep=sleeps.append)
    with pytest.raises(NotReadable) as excinfo:
        reader.get(URL, area="bigquery")
    assert session.attempts == 4
    assert sleeps == [1.0, 2.0, 4.0]
    assert excinfo.value.category == "unavailable"
    assert "network error" in str(excinfo.value)
    assert "after 4 attempts" in str(excinfo.value)


def test_success_that_is_not_json_is_not_readable() -> None:
    reader, _, _ = _reader({("GET", URL): (200, "<html>sign in</html>")})
    with pytest.raises(NotReadable, match="not a JSON object"):
        reader.get(URL, area="bigquery")


def test_errors_name_the_missing_permission_but_not_the_caller() -> None:
    message = (
        "Access Denied: Dataset p-1:d: Permission bigquery.datasets.get denied for "
        "alice@example.com (runs as runner@p-1.iam.gserviceaccount.com)."
    )
    reader, _, _ = _reader({("GET", URL): error(403, message)})
    with pytest.raises(NotReadable) as excinfo:
        reader.get(URL, area="bigquery")
    exc = excinfo.value
    assert exc.category == "permission_denied"
    assert exc.permission == "bigquery.datasets.get"
    assert "alice@example.com" not in str(exc)
    assert "<caller>" in str(exc)
    assert "runner@p-1.iam.gserviceaccount.com" in str(exc)


def test_structured_error_details_win() -> None:
    reader, _, _ = _reader(
        {("GET", URL): permission_denied("bigquery.tables.get")}
    )
    with pytest.raises(NotReadable) as excinfo:
        reader.get(URL, area="bigquery")
    assert excinfo.value.permission == "bigquery.tables.get"
    assert excinfo.value.reason == "IAM_PERMISSION_DENIED"


def test_disabled_api_is_named_without_error_details() -> None:
    message = (
        "Cloud Spanner API has not been used in project p-1 before or it is "
        "disabled. Enable it by visiting https://console.developers.google.com"
        "/apis/api/spanner.googleapis.com/overview?project=p-1 then retry."
    )
    reader, _, _ = _reader({("GET", URL): error(403, message)})
    with pytest.raises(NotReadable) as excinfo:
        reader.get(URL, area="spanner")
    assert excinfo.value.category == "api_disabled"
    assert excinfo.value.service == "spanner.googleapis.com"


def test_quota_project_header_only_after_the_api_asks_for_it() -> None:
    quota_403 = error(
        403, "The API requires a quota project, which is not set by default."
    )
    seen: list[Any] = []

    def route(_url: str, headers: Any) -> tuple[int, Any]:
        seen.append(headers)
        return (200, {"ok": True}) if headers else quota_403

    reader, _, sleeps = _reader({("GET", URL): route})
    reader.quota_project = "p-1"
    assert reader.get(URL, area="bigquery") == {"ok": True}
    assert reader.get(URL, area="bigquery") == {"ok": True}
    assert seen == [
        None,
        {"x-goog-user-project": "p-1"},
        {"x-goog-user-project": "p-1"},
    ]
    assert sleeps == []


def test_without_a_quota_project_the_refusal_is_reported() -> None:
    quota_403 = error(
        403, "The API requires a quota project, which is not set by default."
    )
    reader, cloud, _ = _reader({("GET", URL): quota_403})
    with pytest.raises(NotReadable) as excinfo:
        reader.get(URL, area="bigquery")
    assert excinfo.value.category == "permission_denied"
    assert len(cloud.requests) == 1


def test_google_auth_refresh_and_transport_errors_become_not_readable() -> None:
    class _RefreshFailingSession:
        def __init__(self) -> None:
            self.attempts = 0

        def request(self, *_args: Any, **_kwargs: Any) -> Any:
            self.attempts += 1
            raise RefreshError("Reauthentication is needed.")

    sess = _RefreshFailingSession()
    sleeps: list[float] = []
    reader = ApiReader(sess, sleep=sleeps.append)
    with pytest.raises(NotReadable) as excinfo:
        reader.get(URL, area="bigquery")
    assert excinfo.value.category == "permission_denied"
    assert excinfo.value.status == 401
    assert sess.attempts == 1
    assert sleeps == []

    class _TransportFailingSession:
        def __init__(self) -> None:
            self.attempts = 0

        def request(self, *_args: Any, **_kwargs: Any) -> Any:
            self.attempts += 1
            raise TransportError("token endpoint unreachable")

    tsess = _TransportFailingSession()
    tsleeps: list[float] = []
    treader = ApiReader(tsess, sleep=tsleeps.append)
    with pytest.raises(NotReadable) as texc:
        treader.get(URL, area="bigquery")
    assert texc.value.category == "unavailable"
    assert tsess.attempts == 4
    assert tsleeps == [1.0, 2.0, 4.0]
