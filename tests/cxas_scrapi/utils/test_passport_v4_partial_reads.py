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

"""Passport layout v4: failed reads of parts of resources and of the project.

A table schema, an IAM policy, the MCP server config, an object list, the
project IAM policy or the Cloud Run service list that cannot be read is listed
with the resources that could not be read (manifest, top of PLACEHOLDERS.md,
the resource's README) with what is missing; `strict=True` fails on it.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from passport_v4_cloud import BQ, CRM, GCS, RUN_V2, SM, default_routes
from passport_v4_pull import pull_world, routes_with
from passport_v4_resources import permission_denied
from passport_v4_world import (
    APP_DIR,
    BUCKET,
    PROJECT,
    TOOLBOX_URL,
    app_files,
)

from cxas_scrapi.utils.passport.export import PassportReadError

if TYPE_CHECKING:
    from pathlib import Path

TOOLSET = "toolsets/order_toolbox/order_toolbox.json"
RUN_LIST = (
    f"https://run.googleapis.com/v2/projects/{PROJECT}/locations/-/services"
)
HASH_URL = "https://order-toolbox-abcdef1234-uc.a.run.app"


def _toolset_at(url: str) -> dict[str, str]:
    data = json.loads(app_files()[TOOLSET])
    data["mcpToolset"]["serverAddress"] = f"{url}/mcp"
    return {TOOLSET: json.dumps(data, indent=2) + "\n"}


def test_unreadable_mcp_config_is_listed_and_fails_strict(
    tmp_path: Path,
) -> None:
    routes = routes_with(
        **{
            f"{SM}/toolbox-config/versions/latest:access": permission_denied(
                "secretmanager.versions.access"
            )
        }
    )
    with pytest.raises(PassportReadError) as excinfo:
        pull_world(tmp_path, routes, strict=True)
    (item,) = excinfo.value.report["not_readable"]
    assert item["kind"] == "secretmanager.payload"
    assert item["id"] == (
        "projects/${GCP_PROJECT}/secrets/toolbox-config/versions/latest"
    )
    assert item["what"].startswith("MCP server config")
    assert item["missing_permission"] == (
        "roles/secretmanager.secretAccessor "
        "(permission secretmanager.versions.access)"
    )
    assert "missing from the bundle" in item["impact"]
    assert item["folder"] == "passport/cloud_run/order-toolbox"
    app = tmp_path / APP_DIR
    guide = (app / "PLACEHOLDERS.md").read_text(encoding="utf-8")
    assert guide.index("## Not readable (1)") < guide.index(
        "## Attached Google Cloud resources"
    )
    assert "MCP server config" in guide
    readme = (app / "passport/cloud_run/order-toolbox/README.md").read_text(
        encoding="utf-8"
    )
    assert "## Not readable" in readme
    assert "roles/secretmanager.secretAccessor" in readme
    assert not (app / "passport/cloud_run/order-toolbox/tools.yaml").exists()


def test_unreadable_parts_are_listed_not_hidden_in_warnings(
    tmp_path: Path,
) -> None:
    routes = routes_with(
        **{
            f"{BQ}/orders_ds/tables/orders": permission_denied(
                "bigquery.tables.get"
            ),
            f"{RUN_V2}/order-toolbox:getIamPolicy": permission_denied(
                "run.services.getIamPolicy"
            ),
            f"{GCS}/{BUCKET}/o": permission_denied("storage.objects.list"),
        }
    )
    pull = pull_world(tmp_path, routes)
    manifest = pull.manifest()
    items = {i["what"]: i for i in manifest["not_readable"]}
    assert set(items) == {
        "schema of table `orders`",
        "IAM policy (who may invoke it)",
        "object list",
    }
    assert items["schema of table `orders`"]["missing_permission"] == (
        "roles/bigquery.metadataViewer (permission bigquery.tables.get)"
    )
    assert items["IAM policy (who may invoke it)"]["missing_permission"] == (
        "roles/run.viewer (permission run.services.getIamPolicy)"
    )
    assert items["object list"]["folder"] == "passport/cloud_storage/kb"
    assert len(pull.report["not_readable"]) == 3
    assert not [w for w in manifest["warnings"] if "not read" in w]
    # the resources themselves were read; only these parts are missing
    assert pull.statuses("bigquery.dataset") == {"read"}
    (orders,) = [
        e for e in manifest["resources"]["bigquery"] if e["name"] == "orders_ds"
    ]
    assert [p["what"] for p in orders["not_readable_parts"]] == [
        "schema of table `orders`"
    ]
    assert "passport/bigquery/orders_ds/tables/orders.json" not in pull.files()


def test_unreadable_project_policy_is_listed(tmp_path: Path) -> None:
    routes = default_routes()
    routes[("POST", f"{CRM}/{PROJECT}:getIamPolicy")] = permission_denied(
        "resourcemanager.projects.getIamPolicy"
    )
    pull = pull_world(tmp_path, routes)
    (item,) = pull.manifest()["not_readable"]
    assert item["kind"] == "resourcemanager.project"
    assert item["what"] == "project IAM policy"
    assert item["missing_permission"] == (
        "roles/iam.securityReviewer "
        "(permission resourcemanager.projects.getIamPolicy)"
    )
    assert item["folder"] is None
    assert all(
        i["project_roles"] is None for i in pull.manifest()["identities"]
    )


def test_hash_run_url_is_matched_to_its_service(tmp_path: Path) -> None:
    services = {
        "services": [
            {
                "name": f"projects/{PROJECT}/locations/us-central1/services/order-toolbox",
                "uri": HASH_URL,
                "urls": [TOOLBOX_URL, HASH_URL],
            }
        ]
    }
    routes = routes_with(**{RUN_LIST: (200, services)})
    pull = pull_world(tmp_path, routes, files=_toolset_at(HASH_URL))
    assert pull.cloud.unrouted == []
    assert pull.statuses("run.service") == {"read"}
    assert pull.manifest()["not_readable"] == []
    toolset = pull.text(TOOLSET)
    assert (
        "https://order-toolbox-${GCP_PROJECT_NUMBER}.us-central1.run.app/mcp"
        in toolset
    )
    assert "abcdef1234" not in toolset
    # the walk went on behind the service: its MCP config and datasets
    assert "passport/cloud_run/order-toolbox/tools.yaml" in pull.files()


def test_unlisted_run_services_are_reported_for_hash_urls(
    tmp_path: Path,
) -> None:
    routes = routes_with(**{RUN_LIST: permission_denied("run.services.list")})
    with pytest.raises(PassportReadError) as excinfo:
        pull_world(tmp_path, routes, strict=True, files=_toolset_at(HASH_URL))
    (item,) = excinfo.value.report["not_readable"]
    assert item["kind"] == "run.service"
    assert item["id"].endswith("/locations/-/services")
    assert item["missing_permission"] == (
        "roles/run.viewer (permission run.services.list)"
    )
    assert "external endpoints" in item["impact"]
    statuses = {
        r["kind"]: r["status"] for r in excinfo.value.report["resources"]
    }
    assert statuses["external.endpoint"] == "external"
