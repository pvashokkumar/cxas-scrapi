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

"""Passport layout v4: an agent URL on API Gateway (`*.gateway.dev`).

The gateway is matched against the source project's gateways, read live with
its API config, and the walk goes on to the backends of the API config.
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING

from passport_v4_cloud import default_routes
from passport_v4_pull import pull_world
from passport_v4_resources import api_disabled
from passport_v4_world import FN_SA, PROJECT, app_files

if TYPE_CHECKING:
    from pathlib import Path

APIGW = "https://apigateway.googleapis.com/v1"
GW_LIST = f"{APIGW}/projects/{PROJECT}/locations/-/gateways"
GW_HOST = "loyalty-gw-1a2b3c4d.uc.gateway.dev"
GW = f"projects/{PROJECT}/locations/us-central1/gateways/loyalty-gw"
CFG = f"projects/{PROJECT}/locations/global/apis/loyalty/configs/v1"
OPENAPI = f"""swagger: '2.0'
info:
  title: loyalty
  version: '1'
x-google-backend:
  address: https://us-central1-{PROJECT}.cloudfunctions.net/loyalty-api
paths:
  /status:
    get:
      operationId: get_status
      responses:
        '200':
          description: ok
"""


def _env_on_gateway() -> dict[str, str]:
    env = json.loads(app_files()["environment.json"])
    env["toolsets"]["loyalty_api"]["openApiToolset"]["url"] = (
        f"https://{GW_HOST}"
    )
    return {"environment.json": json.dumps(env, indent=2) + "\n"}


def test_gateway_is_read_with_its_api_config_and_backend(
    tmp_path: Path,
) -> None:
    gateway = {
        "name": GW,
        "defaultHostname": GW_HOST,
        "apiConfig": CFG,
        "state": "ACTIVE",
    }
    contents = base64.b64encode(OPENAPI.encode()).decode()
    routes = default_routes()
    routes[("GET", GW_LIST)] = (200, {"gateways": [gateway]})
    routes[("GET", f"{APIGW}/{GW}")] = (200, gateway)
    routes[("GET", f"{APIGW}/{CFG}")] = (
        200,
        {
            "name": CFG,
            "state": "ACTIVE",
            "gatewayServiceAccount": FN_SA,
            "openapiDocuments": [
                {"document": {"path": "openapi.yaml", "contents": contents}}
            ],
        },
    )
    pull = pull_world(tmp_path, routes, files=_env_on_gateway())
    assert pull.cloud.unrouted == []
    statuses = {r["kind"]: r["status"] for r in pull.report["resources"]}
    assert statuses["apigateway.gateway"] == "read"
    assert statuses["apigateway.apiConfig"] == "read"
    # the function is reached only through the gateway's backend address
    assert statuses["cloudfunctions.function"] == "read"
    assert "external.endpoint" not in statuses
    files = pull.files()
    assert "passport/api_gateway/loyalty-gw/gateway.json" in files
    config = files["passport/api_gateway/loyalty.v1/api_config.json"]
    assert "contents" not in config
    document = files["passport/api_gateway/loyalty.v1/files/openapi.yaml"]
    assert "x-google-backend" in document
    assert "us-central1-${GCP_PROJECT}.cloudfunctions.net" in document
    assert not [rel for rel, text in files.items() if PROJECT in text]
    assert "loyalty-fn-sa@${GCP_PROJECT}" in files["PLACEHOLDERS.md"]


def test_gateway_list_that_cannot_be_read_is_reported(tmp_path: Path) -> None:
    routes = default_routes()
    routes[("GET", GW_LIST)] = api_disabled("apigateway.googleapis.com")
    pull = pull_world(tmp_path, routes, files=_env_on_gateway())
    (item,) = pull.manifest()["not_readable"]
    assert item["kind"] == "apigateway.gateway"
    assert item["missing_permission"].startswith(
        "apigateway.googleapis.com is disabled"
    )
    statuses = {r["kind"]: r["status"] for r in pull.report["resources"]}
    assert statuses["external.endpoint"] == "external"
    assert "apigateway.gateway" not in statuses
