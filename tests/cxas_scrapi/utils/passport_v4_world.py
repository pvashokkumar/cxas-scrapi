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

"""Synthetic CES app for the passport layout v4 tests.

`write_app` writes an app shaped like a CES export (`$env_var` in the agent
files, the values in environment.json): an MCP toolset on Cloud Run whose
config is a mounted secret, an OpenAPI toolset on a Cloud Function that reads
an API key from Secret Manager, a Vertex AI Search data store tool, a Python
tool with SQL and a gs:// path, BigQuery conversation logging, and a tool no
agent uses. passport_v4_cloud answers the REST calls about its resources.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

PROJECT = "src-proj-123"
NUMBER = "111222333444"
ENCODED_PROJECT = PROJECT.replace(
    "-", "--"
)  # as in Cloud Functions image names
APP_ID = "00000000-0000-4000-8000-0000000000aa"
OTHER_APP_ID = (
    "00000000-0000-4000-8000-0000000000bb"  # logs to the same dataset
)
APP_NAME = f"projects/{PROJECT}/locations/us/apps/{APP_ID}"
APP_DIR = "Order_Desk"
BUCKET = f"{PROJECT}-kb"
CES_AGENT = f"service-{NUMBER}@gcp-sa-ces.iam.gserviceaccount.com"
TOOLBOX_SA = f"order-toolbox-sa@{PROJECT}.iam.gserviceaccount.com"
FN_SA = f"loyalty-fn-sa@{PROJECT}.iam.gserviceaccount.com"
TOOLBOX_URL = f"https://order-toolbox-{NUMBER}.us-central1.run.app"
FN_URL = f"https://us-central1-{PROJECT}.cloudfunctions.net/loyalty-api"
DATA_STORE = f"projects/{NUMBER}/locations/us/collections/default_collection/dataStores/policy-docs"
PERSON = "alice@example.com"
TEAM = "agent-team@example.com"
PLAIN_SECRET = "s3cr3t-value-123"


TOOLS_YAML = f"""sources:
  orders_bq:
    kind: bigquery
    project: {PROJECT}
    location: US
    allowedDatasets:
      - orders_ds
  kb:
    kind: cloud-storage
    project: {PROJECT}
    allowedBuckets:
      - {BUCKET}
tools:
  get_order:
    kind: bigquery-sql
    source: orders_bq
    description: One order with its customer.
    parameters:
      - name: order_id
        type: string
        description: Order number.
    statement: |
      SELECT o.order_id, c.email
      FROM `{PROJECT}.orders_ds.orders` o
      JOIN `{PROJECT}.orders_ds.customers` c USING (customer_id)
      WHERE o.order_id = @order_id
toolsets:
  orders:
    - get_order
"""


def _j(data: Any) -> str:
    return json.dumps(data, indent=2) + "\n"


def _python_tool(name: str) -> str:
    return _j(
        {
            "displayName": name,
            "pythonFunction": {
                "name": name,
                "pythonCode": f"tools/{name}/python_function/python_code.py",
            },
        }
    )


def app_files() -> dict[str, str]:
    """rel path -> content of the exported app `Order Desk`."""
    key_version = f"projects/{PROJECT}/secrets/loyalty-api-key/versions/latest"
    return {
        "app.json": _j(
            {
                "name": APP_ID,
                "displayName": "Order Desk",
                "rootAgent": "desk_agent",
                "loggingSettings": {
                    "bigqueryExportSettings": {
                        "enabled": True,
                        "project": "$env_var",
                        "dataset": "$env_var",
                    }
                },
                "modelSettings": {"model": "gemini-3.0-flash-001"},
            }
        ),
        "environment.json": _j(
            {
                "app": {
                    "loggingSettings": {
                        "bigqueryExportSettings": {
                            "project": PROJECT,
                            "dataset": "conv_logs",
                        }
                    }
                },
                "tools": {
                    "search_docs": {
                        "dataStoreTool": {
                            "dataStoreSource": {
                                "dataStore": {"name": DATA_STORE}
                            }
                        }
                    }
                },
                "toolsets": {
                    "loyalty_api": {
                        "openApiToolset": {
                            "apiAuthentication": {
                                "apiKeyConfig": {
                                    "keyName": "x-api-key",
                                    "apiKeySecretVersion": key_version,
                                }
                            },
                            "url": FN_URL,
                        }
                    }
                },
            }
        ),
        "agents/desk_agent/desk_agent.json": _j(
            {
                "displayName": "desk_agent",
                "instruction": "agents/desk_agent/instruction.txt",
                "tools": ["lookup_order", "search_docs"],
                "toolsets": [
                    {"toolset": "order_toolbox", "toolIds": ["get_order"]},
                    {"toolset": "loyalty_api", "toolIds": ["get_status"]},
                ],
            }
        ),
        "agents/desk_agent/instruction.txt": "Use {@TOOL: lookup_order} and {@TOOL: search_docs}.\n",
        "tools/lookup_order/lookup_order.json": _python_tool("lookup_order"),
        "tools/lookup_order/python_function/python_code.py": (
            f'_SQL = "SELECT status FROM `{PROJECT}.orders_ds.orders` WHERE order_id = @id"\n'
            f'_KB = "gs://{BUCKET}/policies/returns.md"\n\n\n'
            "def lookup_order(order_id: str) -> dict:\n"
            '    return {"sql": _SQL, "kb": _KB, "order_id": order_id}\n'
        ),
        "tools/search_docs/search_docs.json": _j(
            {
                "name": "search_docs",
                "displayName": "search_docs",
                "dataStoreTool": {
                    "name": "search_docs",
                    "dataStoreSource": {
                        "dataStore": {
                            "name": "$env_var",
                            "engineType": "SEARCH_ENGINE",
                        }
                    },
                },
            }
        ),
        "tools/unused_tool/unused_tool.json": _python_tool("unused_tool"),
        "tools/unused_tool/python_function/python_code.py": f'_SQL = "SELECT 1 FROM `{PROJECT}.other_ds.t`"\n',
        "toolsets/order_toolbox/order_toolbox.json": _j(
            {
                "name": "order_toolbox",
                "displayName": "order_toolbox",
                "mcpToolset": {
                    "serverAddress": f"{TOOLBOX_URL}/mcp",
                    "apiAuthentication": {"serviceAgentIdTokenAuthConfig": {}},
                },
            }
        ),
        "toolsets/loyalty_api/loyalty_api.json": _j(
            {
                "name": "loyalty_api",
                "displayName": "loyalty_api",
                "openApiToolset": {
                    "openApiSchema": "toolsets/loyalty_api/open_api_toolset/open_api_schema.yaml",
                    "apiAuthentication": {
                        "apiKeyConfig": {
                            "keyName": "$env_var",
                            "apiKeySecretVersion": "$env_var",
                            "requestLocation": "HEADER",
                        }
                    },
                },
            }
        ),
        "toolsets/loyalty_api/open_api_toolset/open_api_schema.yaml": (
            "openapi: 3.0.0\n"
            "info:\n  title: Loyalty\n  version: '1'\n"
            "servers:\n  - url: $env_var\n"
            "paths:\n  /status:\n    get:\n      operationId: get_status\n"
            "      responses:\n        '200':\n          description: ok\n"
        ),
    }


def write_app(base: Path) -> Path:
    """Write the exported app under `base` (as `cxas pull` extracts it)."""
    root = base / APP_DIR
    for rel, text in app_files().items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root
