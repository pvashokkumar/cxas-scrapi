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

"""Canned Google Cloud REST resources and errors of the passport v4 test world."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from passport_v4_world import (
    ENCODED_PROJECT,
    FN_SA,
    FN_URL,
    NUMBER,
    PERSON,
    PLAIN_SECRET,
    PROJECT,
    TOOLBOX_SA,
    TOOLBOX_URL,
)

if TYPE_CHECKING:
    from collections.abc import Callable

Response = tuple[int, Any]


def error(
    code: int,
    message: str,
    *,
    reason: str | None = None,
    permission: str | None = None,
    service: str | None = None,
) -> Response:
    status = {403: "PERMISSION_DENIED", 404: "NOT_FOUND", 503: "UNAVAILABLE"}
    details = []
    if reason:
        meta = {"permission": permission, "service": service}
        details.append(
            {
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "reason": reason,
                "metadata": {k: v for k, v in meta.items() if v},
            }
        )
    body = {
        "code": code,
        "message": message,
        "status": status.get(code, "UNKNOWN"),
    }
    return code, {"error": {**body, "details": details}}


def permission_denied(permission: str) -> Response:
    return error(
        403,
        f"Permission '{permission}' denied on resource (or it may not exist).",
        reason="IAM_PERMISSION_DENIED",
        permission=permission,
    )


def api_disabled(service: str) -> Response:
    return error(
        403,
        f"{service} has not been used in project {NUMBER} before or it is disabled.",
        reason="SERVICE_DISABLED",
        service=service,
    )


UNAVAILABLE = error(503, "The service is currently unavailable.")


def dataset(name: str, access: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "kind": "bigquery#dataset",
        "id": f"{PROJECT}:{name}",
        "selfLink": f"https://bigquery.googleapis.com/bigquery/v2/projects/{PROJECT}/datasets/{name}",
        "datasetReference": {"projectId": PROJECT, "datasetId": name},
        "location": "US",
        "access": access,
    }


def table(dataset: str, name: str, columns: list[str]) -> dict[str, Any]:
    return {
        "kind": "bigquery#table",
        "id": f"{PROJECT}:{dataset}.{name}",
        "selfLink": f"https://bigquery.googleapis.com/bigquery/v2/projects/{PROJECT}/datasets/{dataset}/tables/{name}",
        "tableReference": {
            "projectId": PROJECT,
            "datasetId": dataset,
            "tableId": name,
        },
        "type": "TABLE",
        "schema": {"fields": [{"name": c, "type": "STRING"} for c in columns]},
        "numRows": "7",
    }


def secret(name: str) -> dict[str, Any]:
    return {
        "name": f"projects/{NUMBER}/secrets/{name}",
        "replication": {"automatic": {}},
        "createTime": "2026-01-01T00:00:00Z",
    }


def service_account(email: str) -> dict[str, Any]:
    return {
        "name": f"projects/{PROJECT}/serviceAccounts/{email}",
        "projectId": PROJECT,
        "email": email,
        "displayName": email.split("@", 1)[0],
    }


def knative(
    name: str, meta: dict[str, Any], tspec: dict[str, Any]
) -> dict[str, Any]:
    return {
        "apiVersion": "serving.knative.dev/v1",
        "kind": "Service",
        "metadata": {
            "name": name,
            "namespace": NUMBER,
            "generation": 1,
            **meta,
        },
        "spec": {
            "template": {"spec": tspec},
            "traffic": [{"percent": 100, "latestRevision": True}],
        },
        "status": {"conditions": [{"type": "Ready", "status": "True"}]},
    }


def toolbox_service() -> dict[str, Any]:
    annotations = {
        "serving.knative.dev/creator": PERSON,
        "run.googleapis.com/ingress": "all",
        "run.googleapis.com/custom-audiences": json.dumps(
            [f"{TOOLBOX_URL}/mcp"]
        ),
        "run.googleapis.com/urls": json.dumps([TOOLBOX_URL]),
    }
    container = {
        "image": "us-central1-docker.pkg.dev/toolbox-images/toolbox/toolbox:1.0.0",
        "args": ["--config=/app/tools.yaml"],
        "env": [
            {"name": "API_TOKEN", "value": PLAIN_SECRET},
            {"name": "LOG_LEVEL", "value": "info"},
        ],
        "ports": [{"name": "http1", "containerPort": 8080}],
        "volumeMounts": [{"name": "cfg", "mountPath": "/app"}],
    }
    volume = {
        "name": "cfg",
        "secret": {
            "secretName": "toolbox-config",
            "items": [{"key": "latest", "path": "tools.yaml"}],
        },
    }
    return knative(
        "order-toolbox",
        {"annotations": annotations},
        {
            "serviceAccountName": TOOLBOX_SA,
            "containers": [container],
            "volumes": [volume],
        },
    )


def function_service() -> dict[str, Any]:
    """The Cloud Run service a gen2 Cloud Function runs on (secret by alias)."""
    alias = "secret-00000000-0000-4000-8000-000000000001"
    service = knative(
        "loyalty-api",
        {
            "labels": {"goog-managed-by": "cloudfunctions"},
            "annotations": {
                "cloudfunctions.googleapis.com/function-id": "loyalty-api",
                "run.googleapis.com/invoker-iam-disabled": "true",
            },
        },
        {
            "serviceAccountName": FN_SA,
            "containers": [
                {
                    "image": f"us-central1-docker.pkg.dev/{PROJECT}/gcf-artifacts/{ENCODED_PROJECT}__us--central1__loyalty--api:version_1",
                    "env": [
                        {
                            "name": "LOYALTY_API_KEY",
                            "valueFrom": {
                                "secretKeyRef": {"key": "latest", "name": alias}
                            },
                        }
                    ],
                }
            ],
        },
    )
    service["spec"]["template"]["metadata"] = {
        "annotations": {
            "run.googleapis.com/secrets": f"{alias}:projects/{NUMBER}/secrets/loyalty-api-key"
        }
    }
    return service


def function() -> dict[str, Any]:
    return {
        "name": f"projects/{PROJECT}/locations/us-central1/functions/loyalty-api",
        "environment": "GEN_2",
        "state": "ACTIVE",
        "url": FN_URL,
        "buildConfig": {
            "runtime": "python312",
            "entryPoint": "loyalty_api",
            "dockerRepository": f"projects/{PROJECT}/locations/us-central1/repositories/gcf-artifacts",
            "serviceAccount": f"projects/{PROJECT}/serviceAccounts/{NUMBER}-compute@developer.gserviceaccount.com",
            "source": {
                "storageSource": {
                    "bucket": f"gcf-v2-sources-{NUMBER}-us-central1",
                    "object": "loyalty-api/function-source.zip",
                }
            },
        },
        "serviceConfig": {
            "service": f"projects/{PROJECT}/locations/us-central1/services/loyalty-api",
            "serviceAccountEmail": FN_SA,
            "ingressSettings": "ALLOW_ALL",
            "environmentVariables": {
                "LOG_EXECUTION_ID": "true",
                "SIGNING_SECRET": PLAIN_SECRET,
            },
            "secretEnvironmentVariables": [
                {
                    "key": "LOYALTY_API_KEY",
                    "projectId": NUMBER,
                    "secret": "loyalty-api-key",
                    "version": "latest",
                }
            ],
        },
    }


def quota_gated(body: dict[str, Any]) -> Callable[[str, Any], Response]:
    """Discovery Engine refuses end-user credentials without a quota project."""

    def route(_url: str, headers: Any) -> Response:
        if (headers or {}).get("x-goog-user-project") == PROJECT:
            return 200, body
        return error(
            403,
            "Your application is authenticating by using local Application Default "
            "Credentials. The discoveryengine.googleapis.com API requires a quota "
            "project, which is not set by default.",
        )

    return route
