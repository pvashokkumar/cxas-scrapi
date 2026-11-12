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

"""Vertex AI Search (Discovery Engine) data stores and engines.

Data store: its live config, schema and document list (id, source URI, MIME
type; never content or struct data). Edges: the Cloud Storage objects its
documents were imported from. Engine: its config; edges: its data stores.
"""

from __future__ import annotations

import json
import urllib.parse
from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport import ids
from cxas_scrapi.utils.passport.graph import Edge
from cxas_scrapi.utils.passport.http import NotReadable
from cxas_scrapi.utils.passport.iam import READ_ROLES
from cxas_scrapi.utils.passport.plugins.base import Plugin, dump_json
from cxas_scrapi.utils.passport.scan import GCS_URI_RE

if TYPE_CHECKING:
    from cxas_scrapi.utils.passport.graph import Node, WalkContext

MAX_DOCUMENTS = 1000


def api_base(resource: str) -> str:
    """Regional endpoint for us/eu, global otherwise."""
    location = resource.split("/")[3] if resource.count("/") >= 3 else "global"
    host = (
        "discoveryengine.googleapis.com"
        if location == "global"
        else f"{location}-discoveryengine.googleapis.com"
    )
    return f"https://{host}/v1"


def _stable_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """The schema with `jsonSchema` parsed and every key sorted.

    The API returns the JSON schema as a string whose key order changes from
    one read to the next; sorting keeps two pulls of an unchanged agent equal.
    A `jsonSchema` that is not JSON stays the string it is.
    """
    out = dict(schema)
    raw = out.get("jsonSchema")
    if isinstance(raw, str):
        try:
            out["jsonSchema"] = json.loads(raw)
        except ValueError:
            out["jsonSchema"] = raw
    return json.loads(json.dumps(out, sort_keys=True))


def _document_meta(doc: dict[str, Any]) -> dict[str, Any]:
    content = doc.get("content") or {}
    return {
        "id": doc.get("id"),
        "uri": content.get("uri"),
        "mime_type": content.get("mimeType"),
        "schema_id": doc.get("schemaId"),
        "indexed": bool((doc.get("indexStatus") or {}).get("indexTime")),
    }


class DataStorePlugin(Plugin):
    kind = ids.DATA_STORE
    service = "Vertex AI Search"
    noun = "data store"
    folder = "vertex_ai_search"
    timing_area = "discoveryengine"

    def fetch(self, node: Node, ctx: WalkContext) -> None:
        base = api_base(node.ref.id)
        node.config = ctx.reader.get(
            f"{base}/{node.ref.id}", area=self.timing_area
        )
        node.location = node.ref.id.split("/")[3]
        schema_id = node.config.get("defaultSchemaId") or "default_schema"
        try:
            node.extras["schema"] = ctx.reader.get(
                f"{base}/{node.ref.id}/schemas/{schema_id}",
                area=self.timing_area,
            )
        except NotReadable as exc:
            self._failed(node, ctx, exc, f"schemas/{schema_id}", "schema")
        node.extras["documents"] = self._documents(node, ctx, base)
        if node.config.get("contentConfig") == "PUBLIC_WEBSITE":
            try:
                sites = ctx.reader.get(
                    f"{base}/{node.ref.id}/siteSearchEngine/targetSites?pageSize=100",
                    area=self.timing_area,
                )
                node.extras["target_sites"] = [
                    s.get("providedUriPattern")
                    for s in sites.get("targetSites") or []
                ]
            except NotReadable as exc:
                self._failed(
                    node,
                    ctx,
                    exc,
                    "siteSearchEngine/targetSites",
                    "target sites (the websites it indexes)",
                )

    def _failed(
        self,
        node: Node,
        ctx: WalkContext,
        exc: NotReadable,
        suffix: str,
        what: str,
        impact: str | None = None,
    ) -> None:
        part = {"schemas": "schema", "branches": "documents"}.get(
            suffix.split("/", 1)[0], "targetSites"
        )
        ctx.read_failed(
            exc,
            kind=f"discoveryengine.{part}",
            rid=f"{node.ref.id}/{suffix}",
            what=what,
            role=READ_ROLES[self.kind],
            owner=node.ref,
            impact=impact,
        )

    def _documents(
        self, node: Node, ctx: WalkContext, base: str
    ) -> list[dict[str, Any]]:
        docs: list[dict[str, Any]] = []
        token = ""
        try:
            while len(docs) < MAX_DOCUMENTS:
                url = f"{base}/{node.ref.id}/branches/default_branch/documents?pageSize=100"
                if token:
                    url += f"&pageToken={urllib.parse.quote(token, safe='')}"
                data = ctx.reader.get(url, area=self.timing_area)
                docs += [_document_meta(d) for d in data.get("documents") or []]
                token = str(data.get("nextPageToken") or "")
                if not token:
                    break
        except NotReadable as exc:
            self._failed(
                node,
                ctx,
                exc,
                "branches/default_branch/documents",
                "document list",
                impact="the Cloud Storage files its documents come from are not followed",
            )
        if len(docs) >= MAX_DOCUMENTS:
            node.notes.append(
                f"Only the first {MAX_DOCUMENTS} documents are listed."
            )
        return docs[:MAX_DOCUMENTS]

    def edges(self, node: Node, ctx: WalkContext) -> list[Edge]:
        by_bucket: dict[str, list[str]] = {}
        for doc in node.extras.get("documents") or []:
            m = GCS_URI_RE.match(str(doc.get("uri") or ""))
            if m:
                by_bucket.setdefault(m.group("bucket"), []).append(
                    (m.group("path") or "/")[1:]
                )
        return [
            Edge(
                ids.BUCKET,
                ids.bucket(bucket),
                "documents of this data store were imported from it",
                name=bucket,
                scope=tuple(sorted(o for o in objects if o)),
            )
            for bucket, objects in sorted(by_bucket.items())
        ]

    def resource_folder(self, node: Node, ctx: WalkContext) -> str:
        return node.ref.id.rsplit("/", 1)[-1]

    def files(self, node: Node, ctx: WalkContext) -> dict[str, tuple[str, str]]:
        combined = dict(node.config)
        schema = node.extras.get("schema")
        if schema:
            combined["schema"] = _stable_schema(schema)
        docs = node.extras.get("documents")
        if docs is not None:
            combined["documents"] = docs
        return {
            "data_store.json": (
                dump_json(combined),
                "live data store config, schema and document sources",
            )
        }

    def facts(self, node: Node) -> list[tuple[str, Any]]:
        cfg = node.config
        docs = node.extras.get("documents") or []
        parsing = (
            (cfg.get("documentProcessingConfig") or {}).get(
                "defaultParsingConfig"
            )
        ) or {}
        return [
            ("Display name", cfg.get("displayName")),
            ("Industry vertical", cfg.get("industryVertical")),
            ("Solution types", cfg.get("solutionTypes")),
            ("Content config", cfg.get("contentConfig")),
            ("Default parser", sorted(parsing) or None),
            ("Documents", len(docs)),
            (
                "Document sources",
                sorted({str(d.get("uri")) for d in docs if d.get("uri")}),
            ),
            ("Target sites", node.extras.get("target_sites")),
        ]


class EnginePlugin(Plugin):
    kind = ids.ENGINE
    service = "Vertex AI Search"
    noun = "engine (app)"
    folder = "vertex_ai_search"
    timing_area = "discoveryengine"

    def fetch(self, node: Node, ctx: WalkContext) -> None:
        node.config = ctx.reader.get(
            f"{api_base(node.ref.id)}/{node.ref.id}", area=self.timing_area
        )
        node.location = node.ref.id.split("/")[3]

    def edges(self, node: Node, ctx: WalkContext) -> list[Edge]:
        collection = node.ref.id.split("/engines/")[0]
        return [
            Edge(
                ids.DATA_STORE,
                f"{collection}/dataStores/{ds}",
                "the engine searches this data store",
                location=node.location,
                name=str(ds),
            )
            for ds in node.config.get("dataStoreIds") or []
        ]

    def resource_folder(self, node: Node, ctx: WalkContext) -> str:
        return "engine-" + node.ref.id.rsplit("/", 1)[-1]

    def files(self, node: Node, ctx: WalkContext) -> dict[str, tuple[str, str]]:
        return {"engine.json": (dump_json(node.config), "live engine config")}

    def facts(self, node: Node) -> list[tuple[str, Any]]:
        cfg = node.config
        return [
            ("Display name", cfg.get("displayName")),
            ("Solution type", cfg.get("solutionType")),
            ("Data stores", cfg.get("dataStoreIds")),
            (
                "Search tier",
                (cfg.get("searchEngineConfig") or {}).get("searchTier"),
            ),
            (
                "Search add-ons",
                (cfg.get("searchEngineConfig") or {}).get("searchAddOns"),
            ),
        ]
