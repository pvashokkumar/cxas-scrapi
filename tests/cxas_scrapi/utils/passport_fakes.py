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

"""Test data for the passport tests: a Retail-shaped agent and its live shapes.

`write_retail_agent` writes a plain-pull-shaped export like the live "Retail
Order Support Chat Agent"; `TOOLS_YAML`, `knative_service` and `retail_tables`
are what its MCP Toolbox config, Cloud Run service and BigQuery tables look
like when read live. The project ID and number are synthetic.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

SRC_PROJECT = "src-proj-123"
SRC_NUMBER = "111222333444"
SA_EMAIL = f"retail-toolbox-sa@{SRC_PROJECT}.iam.gserviceaccount.com"
KB_BUCKET = f"{SRC_PROJECT}-retail-kb"
TOOLBOX_URL = f"https://retail-toolbox-{SRC_NUMBER}.us-central1.run.app/mcp"

TOOLS_YAML = f"""# MCP Toolbox config for the Retail agent ({SRC_PROJECT}).

sources:
  retail_bq:
    kind: bigquery
    project: {SRC_PROJECT}
    location: US
    writeMode: blocked
    allowedDatasets:
      - retail_support
    maxQueryResultRows: 25
  retail_kb:
    kind: cloud-storage
    project: {SRC_PROJECT}
    allowedBuckets:
      - {KB_BUCKET}

tools:
  get_order_details:
    kind: bigquery-sql
    source: retail_bq
    description: >-
      Look up one order.
    parameters:
      - name: order_id
        type: string
        description: Order number.
    statement: |
      SELECT o.order_id, c.first_name
      FROM `{SRC_PROJECT}.retail_support.orders` AS o
      JOIN `{SRC_PROJECT}.retail_support.customers` AS c ON c.customer_id = o.customer_id
      WHERE o.order_id = @order_id

  search_products:
    kind: bigquery-sql
    source: retail_bq
    description: Search products.
    parameters:
      - name: query
        type: string
        description: Words.
    statement: |
      SELECT sku, product_name FROM `{SRC_PROJECT}.retail_support.products`
      WHERE STRPOS(LOWER(product_name), LOWER(@query)) > 0

  read_kb_object:
    kind: cloud-storage-read-object
    source: retail_kb
    description: Read one policy document.

toolsets:
  retail_chat_agent:
    - get_order_details
    - search_products
    - read_kb_object
"""


def knative_service() -> dict[str, Any]:
    """Shape of GET .../apis/serving.knative.dev/v1/namespaces/<p>/services/retail-toolbox."""
    return {
        "apiVersion": "serving.knative.dev/v1",
        "kind": "Service",
        "metadata": {
            "name": "retail-toolbox",
            "namespace": SRC_NUMBER,
            "selfLink": f"/apis/serving.knative.dev/v1/namespaces/{SRC_NUMBER}/services/retail-toolbox",
            "uid": "e9483323-0000-0000-0000-7b896974ee08",
            "resourceVersion": "AAZfnvpCdEU",
            "generation": 2,
            "labels": {
                "app": "retail-chat-agent",
                "cloud.googleapis.com/location": "us-central1",
            },
            "annotations": {
                "serving.knative.dev/creator": "admin@example.com",
                "serving.knative.dev/lastModifier": "admin@example.com",
                "run.googleapis.com/client-name": "gcloud",
                "run.googleapis.com/client-version": "592.0.0",
                "run.googleapis.com/custom-audiences": json.dumps(
                    [TOOLBOX_URL]
                ),
                "run.googleapis.com/operation-id": "a12f8a86",
                "run.googleapis.com/ingress": "all",
                "run.googleapis.com/ingress-status": "all",
                "run.googleapis.com/urls": json.dumps(
                    [
                        f"https://retail-toolbox-{SRC_NUMBER}.us-central1.run.app",
                        "https://retail-toolbox-abcde12345-uc.a.run.app",
                    ]
                ),
            },
            "creationTimestamp": "2026-11-06T16:48:40.388066Z",
        },
        "spec": {
            "template": {
                "metadata": {
                    "name": "retail-toolbox-00002-2gn",
                    "labels": {
                        "app": "retail-chat-agent",
                        "client.knative.dev/nonce": "qrjebdfaax",
                    },
                    "annotations": {
                        "autoscaling.knative.dev/maxScale": "3",
                        "run.googleapis.com/client-name": "gcloud",
                        "run.googleapis.com/startup-cpu-boost": "true",
                    },
                },
                "spec": {
                    "containerConcurrency": 80,
                    "timeoutSeconds": 300,
                    "serviceAccountName": SA_EMAIL,
                    "containers": [
                        {
                            "image": "us-central1-docker.pkg.dev/database-toolbox/toolbox/toolbox:1.15.0",
                            "args": [
                                "--config=/app/tools.yaml",
                                "--address=0.0.0.0",
                                "--port=8080",
                            ],
                            "resources": {
                                "limits": {"cpu": "1", "memory": "512Mi"}
                            },
                            "ports": [{"name": "http1", "containerPort": 8080}],
                            "volumeMounts": [
                                {"name": "tools-vol", "mountPath": "/app"}
                            ],
                        }
                    ],
                    "volumes": [
                        {
                            "name": "tools-vol",
                            "secret": {
                                "secretName": "retail-toolbox-tools",
                                "items": [{"key": "1", "path": "tools.yaml"}],
                            },
                        }
                    ],
                },
            },
            "traffic": [{"percent": 100, "latestRevision": True}],
        },
        "status": {
            "url": "https://retail-toolbox-abcde12345-uc.a.run.app",
            "latestReadyRevisionName": "retail-toolbox-00002-2gn",
        },
    }


def table(
    name: str, fields: list[dict[str, Any]], **extra: Any
) -> dict[str, Any]:
    return {
        "tableReference": {
            "projectId": SRC_PROJECT,
            "datasetId": "retail_support",
            "tableId": name,
        },
        "type": "TABLE",
        "schema": {"fields": fields},
        "numRows": "123",
        **extra,
    }


def retail_tables() -> dict[str, dict[str, Any]]:
    return {
        "orders": table(
            "orders",
            [
                {
                    "name": "order_id",
                    "type": "STRING",
                    "mode": "REQUIRED",
                    "description": "Order number, e.g. ORD-1.",
                },
                {"name": "customer_id", "type": "STRING", "mode": "REQUIRED"},
                {"name": "order_date", "type": "DATE", "mode": "REQUIRED"},
                {"name": "total_amount", "type": "NUMERIC"},
                {"name": "tags", "type": "STRING", "mode": "REPEATED"},
                {
                    "name": "shipping",
                    "type": "RECORD",
                    "fields": [
                        {"name": "carrier", "type": "STRING"},
                        {"name": "delivered_at", "type": "TIMESTAMP"},
                    ],
                },
            ],
            description="Order headers.",
            timePartitioning={"type": "DAY", "field": "order_date"},
            clustering={"fields": ["customer_id"]},
        ),
        "customers": table(
            "customers",
            [
                {"name": "customer_id", "type": "STRING", "mode": "REQUIRED"},
                {"name": "first_name", "type": "STRING"},
                {"name": "is_vip", "type": "BOOLEAN"},
                {"name": "visits", "type": "INTEGER"},
            ],
        ),
        "products": table(
            "products",
            [
                {"name": "sku", "type": "STRING", "mode": "REQUIRED"},
                {
                    "name": "product_name",
                    "type": "STRING",
                    "description": "Name 'as sold'.",
                },
                {"name": "unit_price", "type": "FLOAT"},
            ],
        ),
    }


def write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        data if isinstance(data, str) else json.dumps(data, indent=2) + "\n",
        encoding="utf-8",
    )


def write_retail_agent(root: Path) -> Path:
    """A plain-pull-shaped export of an agent like the live Retail agent."""
    write(
        root / "app.json",
        {
            "name": "00000000-0000-4000-8000-000000000002",
            "displayName": "Retail Order Support Chat Agent",
            "rootAgent": "order_support_agent",
            "modelSettings": {"model": "gemini-3.0-flash-001"},
        },
    )
    write(
        root / "agents/order_support_agent/order_support_agent.json",
        {
            "name": "order_support_agent",
            "displayName": "order_support_agent",
            "instruction": "agents/order_support_agent/instruction.txt",
            "tools": [
                "check_return_eligibility",
                "end_session",
                "get_store_policy",
            ],
            "toolsets": [
                {
                    "toolset": "retail_toolbox",
                    "toolIds": ["get_order_details", "search_products"],
                }
            ],
        },
    )
    write(
        root / "agents/order_support_agent/instruction.txt",
        "Use {@TOOL: get_store_policy} for policies. Prices are shown as ${amount:.2f}.\n",
    )
    write(
        root / "tools/check_return_eligibility/check_return_eligibility.json",
        {
            "name": "check_return_eligibility",
            "displayName": "check_return_eligibility",
            "pythonFunction": {
                "name": "check_return_eligibility",
                "pythonCode": "tools/check_return_eligibility/python_function/python_code.py",
            },
        },
    )
    write(
        root / "tools/check_return_eligibility/python_function/python_code.py",
        f'"""Return checks."""\n\n_RETURN_POLICY_URI = "gs://{KB_BUCKET}/policies/return_policy.json"\n\n\n'
        "def check_return_eligibility(order_id: str) -> dict:\n"
        '    return {"uri": _RETURN_POLICY_URI}\n',
    )
    write(
        root / "tools/get_store_policy/get_store_policy.json",
        {
            "name": "get_store_policy",
            "displayName": "get_store_policy",
            "pythonFunction": {
                "name": "get_store_policy",
                "pythonCode": "tools/get_store_policy/python_function/python_code.py",
            },
        },
    )
    write(
        root / "tools/get_store_policy/python_function/python_code.py",
        '"""Store policies."""\n\n_POLICY_DOCUMENTS = {\n'
        f'    "returns": "gs://{KB_BUCKET}/policies/return_policy.json",\n'
        f'    "shipping": "gs://{KB_BUCKET}/policies/shipping_policy.md",\n'
        "}\n\n\ndef get_store_policy(topic: str) -> dict:\n"
        '    return {"uri": _POLICY_DOCUMENTS.get(topic)}\n',
    )
    write(
        root / "toolsets/retail_toolbox/retail_toolbox.json",
        '{\n  "name": "retail_toolbox",\n  "displayName": "retail_toolbox",\n  "mcpToolset": {\n'
        f'    "serverAddress": "{TOOLBOX_URL}",\n'
        '    "apiAuthentication": {\n      "serviceAgentIdTokenAuthConfig": {\n      }\n    }\n  },\n'
        '  "description": "MCP Toolbox on Cloud Run."\n}\n',
    )
    write(root / "pythonEnvFiles/pythonEnvFiles.json", "{}\n")
    return root


def snapshot(root: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(root)): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }
