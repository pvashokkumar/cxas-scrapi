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

"""Every other kind: the live config from the service's REST API.

`GENERIC_KINDS` maps a kind to its service, folder, read URL and read role
(for resource names recognized by `passport.resource_names.kind_of_resource_name`).
Kinds without a reader (an unknown kind, a URL outside Google Cloud) still get a
folder with a README that says what the agent references.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport import ids
from cxas_scrapi.utils.passport.plugins.base import Plugin, dump_json

if TYPE_CHECKING:
    from collections.abc import Callable

    from cxas_scrapi.utils.passport.graph import Node, WalkContext


def _loc(rid: str) -> str:
    parts = rid.split("/")
    return (
        parts[3]
        if len(parts) > 3 and parts[2] == "locations"
        else "us-central1"
    )


@dataclass(frozen=True)
class GenericKind:
    service: str
    noun: str
    folder: str
    url: Callable[[str], str]
    read_role: str


def _simple(host: str, version: str) -> Callable[[str], str]:
    return lambda rid: f"https://{host}/{version}/{rid}"


def _VERTEX(rid: str) -> str:  # noqa: N802  (table constant)
    return f"https://{_loc(rid)}-aiplatform.googleapis.com/v1beta1/{rid}"


GENERIC_KINDS: dict[str, GenericKind] = {
    "sqladmin.instance": GenericKind(
        "Cloud SQL",
        "instance",
        "cloud_sql",
        _simple("sqladmin.googleapis.com", "v1"),
        "roles/cloudsql.viewer",
    ),
    "spanner.database": GenericKind(
        "Cloud Spanner",
        "database",
        "spanner",
        _simple("spanner.googleapis.com", "v1"),
        "roles/spanner.viewer",
    ),
    "alloydb.cluster": GenericKind(
        "AlloyDB",
        "cluster",
        "alloydb",
        _simple("alloydb.googleapis.com", "v1"),
        "roles/alloydb.viewer",
    ),
    "alloydb.instance": GenericKind(
        "AlloyDB",
        "instance",
        "alloydb",
        _simple("alloydb.googleapis.com", "v1"),
        "roles/alloydb.viewer",
    ),
    "firestore.database": GenericKind(
        "Firestore",
        "database",
        "firestore",
        _simple("firestore.googleapis.com", "v1"),
        "roles/datastore.viewer",
    ),
    "bigtable.instance": GenericKind(
        "Bigtable",
        "instance",
        "bigtable",
        _simple("bigtableadmin.googleapis.com", "v2"),
        "roles/bigtable.viewer",
    ),
    "pubsub.topic": GenericKind(
        "Pub/Sub",
        "topic",
        "pubsub",
        _simple("pubsub.googleapis.com", "v1"),
        "roles/pubsub.viewer",
    ),
    "pubsub.subscription": GenericKind(
        "Pub/Sub",
        "subscription",
        "pubsub",
        _simple("pubsub.googleapis.com", "v1"),
        "roles/pubsub.viewer",
    ),
    "cloudtasks.queue": GenericKind(
        "Cloud Tasks",
        "queue",
        "cloud_tasks",
        _simple("cloudtasks.googleapis.com", "v2"),
        "roles/cloudtasks.viewer",
    ),
    "workflows.workflow": GenericKind(
        "Workflows",
        "workflow",
        "workflows",
        _simple("workflows.googleapis.com", "v1"),
        "roles/workflows.viewer",
    ),
    "aiplatform.endpoint": GenericKind(
        "Vertex AI", "endpoint", "vertex_ai", _VERTEX, "roles/aiplatform.viewer"
    ),
    "aiplatform.ragCorpus": GenericKind(
        "Vertex AI",
        "RAG corpus",
        "vertex_ai",
        _VERTEX,
        "roles/aiplatform.viewer",
    ),
    "aiplatform.indexEndpoint": GenericKind(
        "Vertex AI",
        "index endpoint",
        "vertex_ai",
        _VERTEX,
        "roles/aiplatform.viewer",
    ),
    "aiplatform.featureOnlineStore": GenericKind(
        "Vertex AI",
        "feature online store",
        "vertex_ai",
        _VERTEX,
        "roles/aiplatform.viewer",
    ),
    "aiplatform.cachedContent": GenericKind(
        "Vertex AI",
        "cached content",
        "vertex_ai",
        _VERTEX,
        "roles/aiplatform.viewer",
    ),
    "modelarmor.template": GenericKind(
        "Model Armor",
        "template",
        "model_armor",
        lambda rid: (
            f"https://modelarmor.{_loc(rid)}.rep.googleapis.com/v1/{rid}"
        ),
        "roles/modelarmor.viewer",
    ),
    "dlp.inspectTemplate": GenericKind(
        "Sensitive Data Protection",
        "inspect template",
        "dlp",
        _simple("dlp.googleapis.com", "v2"),
        "roles/dlp.reader",
    ),
    "dlp.deidentifyTemplate": GenericKind(
        "Sensitive Data Protection",
        "de-identify template",
        "dlp",
        _simple("dlp.googleapis.com", "v2"),
        "roles/dlp.reader",
    ),
    "vpcaccess.connector": GenericKind(
        "Serverless VPC Access",
        "connector",
        "vpc_access",
        _simple("vpcaccess.googleapis.com", "v1"),
        "roles/vpcaccess.viewer",
    ),
    "servicedirectory.service": GenericKind(
        "Service Directory",
        "service",
        "service_directory",
        _simple("servicedirectory.googleapis.com", "v1"),
        "roles/servicedirectory.viewer",
    ),
    "connectors.connection": GenericKind(
        "Integration Connectors",
        "connection",
        "integration_connectors",
        _simple("connectors.googleapis.com", "v1"),
        "roles/connectors.viewer",
    ),
    "appengine.app": GenericKind(
        "App Engine",
        "application",
        "app_engine",
        _simple("appengine.googleapis.com", "v1"),
        "roles/appengine.appViewer",
    ),
}


class GenericPlugin(Plugin):
    """Live config of a kind from GENERIC_KINDS; README only for others."""

    kind = "generic"
    service = "Google Cloud"
    noun = "resource"
    folder = "other"
    timing_area = "generic"

    def _spec(self, node: Node) -> GenericKind | None:
        return GENERIC_KINDS.get(node.kind)

    def can_read(self, node: Node) -> bool:
        return self._spec(node) is not None

    def read_role_of(self, node: Node) -> str | None:
        spec = self._spec(node)
        return spec.read_role if spec else None

    def service_of(self, node: Node) -> str:
        spec = self._spec(node)
        return spec.service if spec else self.service

    def noun_of(self, node: Node) -> str:
        spec = self._spec(node)
        return spec.noun if spec else f"resource ({node.kind})"

    def folder_of(self, node: Node) -> str:
        spec = self._spec(node)
        return spec.folder if spec else self.folder

    def fetch(self, node: Node, ctx: WalkContext) -> None:
        spec = self._spec(node)
        if spec is not None:
            node.config = ctx.reader.get(spec.url(node.ref.id), area=node.kind)

    def files(self, node: Node, ctx: WalkContext) -> dict[str, tuple[str, str]]:
        if not node.config:
            return {}
        return {"config.json": (dump_json(node.config), "live config")}

    def facts(self, node: Node) -> list[tuple[str, Any]]:
        cfg = node.config
        keys = (
            "displayName",
            "state",
            "databaseVersion",
            "region",
            "tier",
            "version",
            "type",
            "ipConfiguration",
            "network",
            "description",
            "labels",
        )
        return [(k, cfg.get(k)) for k in keys if k in cfg]


class ExternalEndpointPlugin(Plugin):
    """A URL outside Google Cloud (or one the passport cannot map to a resource)."""

    kind = ids.ENDPOINT
    service = "External"
    noun = "endpoint"
    folder = "external"
    readable = False

    def facts(self, node: Node) -> list[tuple[str, Any]]:
        return [
            ("URLs the agent calls", node.hints.get("urls") or [node.ref.id])
        ]
