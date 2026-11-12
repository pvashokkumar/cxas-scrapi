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
# ruff: noqa: E501

"""Fake Google Cloud for the passport v4 tests: the REST calls `ApiReader` makes.

`FakeCloud` stands in for the HTTP session of `ApiReader`: it answers
(method, URL without query) from `default_routes()` and records every request.
"""

from __future__ import annotations

import base64
import io
import json
import zipfile
from collections.abc import Callable
from typing import Any

from passport_v4_resources import (
    Response,
    dataset,
    error,
    function,
    function_service,
    quota_gated,
    secret,
    service_account,
    table,
    toolbox_service,
)
from passport_v4_world import (
    APP_ID,
    BUCKET,
    CES_AGENT,
    DATA_STORE,
    FN_SA,
    NUMBER,
    OTHER_APP_ID,
    PERSON,
    PROJECT,
    TEAM,
    TOOLBOX_SA,
    TOOLS_YAML,
)

Route = Response | list[Response] | Callable[[str, Any], Response]
CRM = "https://cloudresourcemanager.googleapis.com/v1/projects"
BQ = f"https://bigquery.googleapis.com/bigquery/v2/projects/{PROJECT}/datasets"
RUN_KN = f"https://us-central1-run.googleapis.com/apis/serving.knative.dev/v1/namespaces/{PROJECT}/services"
RUN_V2 = f"https://run.googleapis.com/v2/projects/{PROJECT}/locations/us-central1/services"
SM = f"https://secretmanager.googleapis.com/v1/projects/{PROJECT}/secrets"
GCS = "https://storage.googleapis.com/storage/v1/b"
DS = f"https://us-discoveryengine.googleapis.com/v1/projects/{PROJECT}/locations/us/collections/default_collection/dataStores/policy-docs"
FN = f"https://cloudfunctions.googleapis.com/v2/projects/{PROJECT}/locations/us-central1/functions/loyalty-api"
IAM = f"https://iam.googleapis.com/v1/projects/{PROJECT}/serviceAccounts"
AR = f"https://artifactregistry.googleapis.com/v1/projects/{PROJECT}/locations/us-central1/repositories/gcf-artifacts"


def _function_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "main.py",
            f'PROJECT = "{PROJECT}"\ndef loyalty_api(request):\n    return {{"ok": True}}\n',
        )
        zf.writestr("requirements.txt", "functions-framework==3.*\n")
    return buf.getvalue()


def default_routes() -> dict[tuple[str, str], Route]:
    ces = f"serviceAccount:{CES_AGENT}"
    accessor = "roles/secretmanager.secretAccessor"
    tools_yaml = base64.b64encode(TOOLS_YAML.encode()).decode()
    doc_uri = f"gs://{BUCKET}/policies/returns.md"
    g = "GET"
    return {
        (g, f"{CRM}/{PROJECT}"): (
            200,
            {"projectId": PROJECT, "projectNumber": NUMBER},
        ),
        ("POST", f"{CRM}/{PROJECT}:getIamPolicy"): (
            200,
            {
                "bindings": [
                    {"role": "roles/owner", "members": [f"user:{PERSON}"]},
                    {"role": "roles/ces.serviceAgent", "members": [ces]},
                    {
                        "role": "roles/bigquery.jobUser",
                        "members": [f"serviceAccount:{TOOLBOX_SA}"],
                    },
                ]
            },
        ),
        (g, f"{BQ}/orders_ds"): (
            200,
            dataset(
                "orders_ds",
                [
                    {"role": "READER", "userByEmail": TOOLBOX_SA},
                    {"role": "OWNER", "userByEmail": PERSON},
                    {"role": "OWNER", "specialGroup": "projectOwners"},
                ],
            ),
        ),
        (g, f"{BQ}/orders_ds/tables/orders"): (
            200,
            table("orders_ds", "orders", ["order_id", "customer_id", "status"]),
        ),
        (g, f"{BQ}/orders_ds/tables/orders/data"): (
            200,
            {
                "kind": "bigquery#tableDataList",
                "totalRows": "1",
                "rows": [
                    {
                        "f": [
                            {"v": "ORD-1"},
                            {"v": "CUST-1"},
                            {"v": "DELIVERED"},
                        ]
                    }
                ],
            },
        ),
        (g, f"{BQ}/orders_ds/tables/customers"): (
            200,
            table("orders_ds", "customers", ["customer_id", "email"]),
        ),
        (g, f"{BQ}/orders_ds/tables/customers/data"): (
            200,
            {
                "kind": "bigquery#tableDataList",
                "totalRows": "1",
                "rows": [
                    {
                        "f": [
                            {"v": "CUST-1"},
                            {"v": "maya@example.com"},
                        ]
                    }
                ],
            },
        ),
        (g, f"{BQ}/conv_logs"): (
            200,
            dataset(
                "conv_logs", [{"role": "WRITER", "userByEmail": CES_AGENT}]
            ),
        ),
        (g, f"{BQ}/conv_logs/tables"): (
            200,
            {
                "tables": [
                    {"tableReference": {"tableId": APP_ID}},
                    {"tableReference": {"tableId": OTHER_APP_ID}},
                ]
            },
        ),
        (g, f"{BQ}/conv_logs/tables/{APP_ID}"): (
            200,
            table("conv_logs", APP_ID, ["session_id", "turn"]),
        ),
        (g, f"{RUN_KN}/order-toolbox"): (200, toolbox_service()),
        (g, f"{RUN_V2}/order-toolbox:getIamPolicy"): (
            200,
            {
                "bindings": [
                    {
                        "role": "roles/run.invoker",
                        "members": [ces, f"user:{PERSON}"],
                    }
                ]
            },
        ),
        (g, f"{RUN_KN}/loyalty-api"): (200, function_service()),
        (g, f"{RUN_V2}/loyalty-api:getIamPolicy"): (200, {"etag": "BwY="}),
        (g, f"{SM}/toolbox-config"): (200, secret("toolbox-config")),
        (g, f"{SM}/toolbox-config:getIamPolicy"): (
            200,
            {
                "bindings": [
                    {
                        "role": accessor,
                        "members": [f"serviceAccount:{TOOLBOX_SA}"],
                    }
                ]
            },
        ),
        (g, f"{SM}/toolbox-config/versions/latest:access"): (
            200,
            {"payload": {"data": tools_yaml}},
        ),
        (g, f"{SM}/loyalty-api-key"): (200, secret("loyalty-api-key")),
        (g, f"{SM}/loyalty-api-key:getIamPolicy"): (
            200,
            {
                "bindings": [
                    {
                        "role": accessor,
                        "members": [f"serviceAccount:{FN_SA}", ces],
                    },
                    {
                        "role": "roles/secretmanager.admin",
                        "members": [f"group:{TEAM}"],
                    },
                ]
            },
        ),
        (g, f"{GCS}/{BUCKET}"): (
            200,
            {
                "name": BUCKET,
                "projectNumber": NUMBER,
                "location": "US",
                "storageClass": "STANDARD",
            },
        ),
        (g, f"{GCS}/{BUCKET}/iam"): (
            200,
            {
                "bindings": [
                    {
                        "role": "roles/storage.objectViewer",
                        "members": [
                            f"serviceAccount:{TOOLBOX_SA}",
                            f"user:{PERSON}",
                        ],
                    }
                ]
            },
        ),
        (g, f"{GCS}/{BUCKET}/o"): (
            200,
            {
                "items": [
                    {
                        "name": "policies/returns.md",
                        "size": "120",
                        "contentType": "text/markdown",
                        "updated": "2026-01-01T00:00:00Z",
                    }
                ]
            },
        ),
        (g, f"{GCS}/{BUCKET}/o/policies%2Freturns.md"): lambda url, _h: (
            (
                200,
                f"# Return policy for {PROJECT}\n30 days.\n".encode(),
            )
            if "alt=media" in url
            else (
                200,
                {
                    "name": "policies/returns.md",
                    "size": "120",
                    "contentType": "text/markdown",
                    "updated": "2026-01-01T00:00:00Z",
                },
            )
        ),
        (
            g,
            f"{GCS}/gcf-v2-sources-{NUMBER}-us-central1/o/loyalty-api%2Ffunction-source.zip",
        ): (
            200,
            _function_zip(),
        ),
        (g, DS): quota_gated(
            {
                "name": DATA_STORE,
                "displayName": "Policy docs",
                "industryVertical": "GENERIC",
                "contentConfig": "CONTENT_REQUIRED",
            }
        ),
        (g, f"{DS}/schemas/default_schema"): quota_gated(
            {
                "name": f"{DATA_STORE}/schemas/default_schema",
                "jsonSchema": json.dumps({"type": "object"}),
            }
        ),
        (g, f"{DS}/branches/default_branch/documents"): quota_gated(
            {
                "documents": [
                    {
                        "id": "returns",
                        "content": {"mimeType": "text/plain", "uri": doc_uri},
                    }
                ]
            }
        ),
        (g, FN): (200, function()),
        (g, f"{FN}:getIamPolicy"): (200, {"etag": "BwY="}),
        (g, f"{IAM}/{TOOLBOX_SA}"): (200, service_account(TOOLBOX_SA)),
        (g, f"{IAM}/{TOOLBOX_SA}/keys"): (200, {"keys": []}),
        (g, f"{IAM}/{FN_SA}"): (200, service_account(FN_SA)),
        (g, f"{IAM}/{FN_SA}/keys"): (200, {"keys": []}),
        (g, AR): (
            200,
            {
                "name": AR.split("/v1/", 1)[1],
                "format": "DOCKER",
                "mode": "STANDARD_REPOSITORY",
            },
        ),
    }


class FakeResponse:
    def __init__(self, status_code: int, body: Any) -> None:
        self.status_code = status_code
        self._body = body
        if isinstance(body, (bytes, bytearray)):
            self.content = bytes(body)
            self.text = self.content.decode("utf-8", errors="replace")
        elif isinstance(body, str):
            self.text = body
            self.content = body.encode("utf-8")
        else:
            self.text = json.dumps(body)
            self.content = self.text.encode("utf-8")

    def json(self) -> Any:
        if isinstance(self._body, str):
            raise ValueError("not JSON")
        return self._body


class FakeCloud:
    """HTTP session stand-in: routes (method, URL without query) to responses.

    A route is a response, a list of responses (served in order, the last one
    repeats) or a callable (url, headers) -> response. Unrouted calls get 404
    and are recorded in `unrouted`.
    """

    def __init__(
        self, routes: dict[tuple[str, str], Route] | None = None
    ) -> None:
        self.routes = default_routes() if routes is None else routes
        self.requests: list[tuple[str, str, dict[str, str] | None]] = []
        self.unrouted: list[str] = []

    def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        headers = kwargs.get("headers")
        self.requests.append((method, url, headers))
        route = self.routes.get((method, url.split("?", 1)[0]))
        if route is None:
            self.unrouted.append(f"{method} {url}")
            return FakeResponse(*error(404, f"{url} not found"))
        if callable(route):
            return FakeResponse(*route(url, headers))
        if isinstance(route, list):
            return FakeResponse(*(route.pop(0) if len(route) > 1 else route[0]))
        return FakeResponse(*route)

    def urls(self, needle: str = "") -> list[str]:
        return [url for _, url, _ in self.requests if needle in url]
