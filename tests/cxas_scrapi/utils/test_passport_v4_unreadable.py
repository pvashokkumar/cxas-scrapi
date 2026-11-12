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

"""Passport layout v4: resources that cannot be read, retries, --strict.

A resource that cannot be read is recorded as not readable (the error and
what is missing), listed first in PLACEHOLDERS.md and in the manifest, and
the pull goes on; `strict=True` raises PassportReadError after writing.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from passport_v4_cloud import BQ, DS, FN, RUN_KN, SM, default_routes
from passport_v4_pull import pull_world, routes_with
from passport_v4_resources import (
    UNAVAILABLE,
    api_disabled,
    error,
    permission_denied,
)
from passport_v4_world import APP_DIR, NUMBER

from cxas_scrapi.utils.passport.export import PassportReadError

if TYPE_CHECKING:
    from pathlib import Path

DS_DENIED = permission_denied("discoveryengine.dataStores.get")


def test_permission_denied_is_recorded_and_listed_first(tmp_path: Path) -> None:
    pull = pull_world(tmp_path, routes_with(**{DS: DS_DENIED}))
    (item,) = pull.manifest()["not_readable"]
    assert item["kind"] == "discoveryengine.dataStore"
    assert item["error_category"] == "permission_denied"
    assert item["missing_permission"] == (
        "roles/discoveryengine.viewer (permission discoveryengine.dataStores.get)"
    )
    assert pull.report["not_readable"][0]["id"].endswith(
        "/dataStores/policy-docs"
    )
    readme = pull.text("passport/vertex_ai_search/policy-docs/README.md")
    assert "NOT READABLE" in readme
    assert "roles/discoveryengine.viewer" in readme
    guide = pull.text("PLACEHOLDERS.md")
    assert guide.index("Not readable") < guide.index(
        "Attached Google Cloud resources"
    )
    # the rest of the walk went on
    assert pull.statuses("cloudfunctions.function") == {"read"}
    assert pull.statuses("storage.bucket") == {"read"}


def test_deleted_resource_is_reported_as_not_found(tmp_path: Path) -> None:
    routes = routes_with(**{f"{SM}/loyalty-api-key": error(404, "Not found.")})
    pull = pull_world(tmp_path, routes)
    (item,) = pull.manifest()["not_readable"]
    assert item["kind"] == "secretmanager.secret"
    assert item["error_category"] == "not_found"
    assert (
        item["missing_permission"]
        == "none: the resource was deleted or renamed"
    )


def test_disabled_api_is_reported_and_never_enabled(tmp_path: Path) -> None:
    routes = routes_with(**{FN: api_disabled("cloudfunctions.googleapis.com")})
    pull = pull_world(tmp_path, routes)
    (item,) = pull.manifest()["not_readable"]
    assert item["error_category"] == "api_disabled"
    assert item["missing_permission"].startswith(
        "cloudfunctions.googleapis.com is disabled"
    )
    # the error text names the project number: scrubbed like everything else
    assert NUMBER not in json.dumps(pull.manifest())
    for method, url, _ in pull.cloud.requests:
        assert "serviceusage" not in url
        assert method == "GET" or url.endswith(":getIamPolicy")
    # Without the function its Cloud Run service is never reached.
    assert not pull.cloud.urls(f"{RUN_KN}/loyalty-api")


def test_server_errors_are_retried_with_backoff(tmp_path: Path) -> None:
    routes = default_routes()
    good = routes[("GET", f"{BQ}/orders_ds")]
    routes[("GET", f"{BQ}/orders_ds")] = [UNAVAILABLE, UNAVAILABLE, good]
    pull = pull_world(tmp_path, routes)
    assert pull.sleeps == [1.0, 2.0]
    assert pull.statuses("bigquery.dataset") == {"read"}
    retried = pull.manifest()["introspection"]["transient_errors_retried"]
    assert [r["status"] for r in retried] == [503, 503]


def test_server_errors_that_persist_make_the_resource_unavailable(
    tmp_path: Path,
) -> None:
    pull = pull_world(
        tmp_path, routes_with(**{f"{BQ}/orders_ds": [UNAVAILABLE]})
    )
    assert pull.sleeps == [1.0, 2.0, 4.0]
    (item,) = pull.manifest()["not_readable"]
    assert item["error_category"] == "unavailable"
    assert "after 4 attempts" in item["error"]


def test_strict_raises_after_writing_the_bundle(tmp_path: Path) -> None:
    with pytest.raises(PassportReadError) as excinfo:
        pull_world(tmp_path, routes_with(**{DS: DS_DENIED}), strict=True)
    app = tmp_path / APP_DIR
    assert (app / "PLACEHOLDERS.md").is_file()
    manifest = json.loads((app / "passport" / "manifest.json").read_text())
    assert len(manifest["not_readable"]) == 1
    assert excinfo.value.report["not_readable"][0]["error_category"] == (
        "permission_denied"
    )


def test_strict_passes_when_everything_is_readable(tmp_path: Path) -> None:
    pull = pull_world(tmp_path, strict=True)
    assert pull.report["not_readable"] == []
