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

"""Seeds of the resource graph: what the agent files reference directly.

Structured references first (toolset server URLs and OpenAPI servers,
authentication secrets and service accounts, data store tools, connector
and file-search tools, app.json logging and certificate settings), then a text
scan of the files the active agents run (Python tools and callbacks,
instructions) for URLs, `gs://` paths, secrets, SQL tables and other resource
names. Tools no active agent uses are skipped.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import yaml

from cxas_scrapi.utils.passport import ids, seed_refs
from cxas_scrapi.utils.passport.files import (
    read_json,
    read_text,
    safe_bundle_file,
    usage_label,
)
from cxas_scrapi.utils.passport.graph import Evidence
from cxas_scrapi.utils.passport.resource_names import kind_of_resource_name
from cxas_scrapi.utils.passport.scan import SECRET_RE
from cxas_scrapi.utils.passport.seed_refs import overlay
from cxas_scrapi.utils.passport.urls import classify_url

if TYPE_CHECKING:
    from pathlib import Path

    from cxas_scrapi.utils.passport.graph import ResourceGraph
    from cxas_scrapi.utils.passport.scan import Refs


def _line(text: str, needle: str) -> int | None:
    pos = text.find(needle) if needle else -1
    return text.count("\n", 0, pos) + 1 if pos >= 0 else None


class Seeder:
    """Adds the agent's direct references to a ResourceGraph."""

    def __init__(self, graph: ResourceGraph, root: Path) -> None:
        self.graph = graph
        self.ctx = graph.ctx
        self.root = root
        self.unused_tools: list[str] = []
        self.notes: list[str] = []
        self._also: tuple[str, ...] = ()  # other files that may hold a value

    # -- helpers ------------------------------------------------------------

    def _ev(self, rel: str, needle: str, relation: str) -> Evidence:
        for candidate in (rel, *self._also):
            line = _line(read_text(self.root / candidate) or "", needle)
            if line is not None:
                rel = candidate
                break
        else:
            line = None
        return Evidence(
            f"{usage_label(rel, line)}: {relation}", file=rel, line=line
        )

    def add_url(self, url: str, ev: Evidence) -> None:
        target = classify_url(url, self.ctx)
        self.graph.add(
            target.kind,
            target.id,
            ev,
            project=target.project,
            location=target.location,
            name=target.name,
            hints=target.hints,
        )

    def add_secret_version(self, value: str, ev: Evidence) -> None:
        m = SECRET_RE.search(str(value or ""))
        if m and not m.group("project").startswith("$"):
            project = self.ctx.project_key(m.group("project"))
            self.graph.add(
                ids.SECRET,
                ids.secret(self.ctx, project, m.group("secret")),
                ev,
                project=project,
            )

    def resolve_name(
        self, value: str
    ) -> tuple[str, str, str | None, str | None] | None:
        """(kind, id, project, location) of a resource name, source project normalized."""
        found = kind_of_resource_name(str(value or ""))
        if not found:
            return None
        kind, rid = found
        parts = rid.split("/")
        project = location = None
        if len(parts) > 1 and parts[0] == "projects":
            project = self.ctx.project_key(parts[1])
            rid = "/".join(["projects", str(project), *parts[2:]])
        if len(parts) > 3 and parts[2] == "locations":
            location = parts[3]
        return kind, rid, project, location

    def add_name(self, value: str, ev: Evidence) -> None:
        resolved = self.resolve_name(value)
        if resolved:
            kind, rid, project, location = resolved
            self.graph.add(kind, rid, ev, project=project, location=location)

    # -- structured references ---------------------------------------------

    def auth(self, auth: Any, rel: str, owner: str) -> None:
        if not isinstance(auth, dict):
            return
        key = auth.get("apiKeyConfig") or {}
        if key.get("apiKeySecretVersion"):
            where = f"{str(key.get('requestLocation') or 'request').lower()} `{key.get('keyName')}`"
            self.add_secret_version(
                key["apiKeySecretVersion"],
                self._ev(
                    rel,
                    key["apiKeySecretVersion"],
                    f"API key that CES sends to {owner} ({where})",
                ),
            )
        oauth = auth.get("oauthConfig") or {}
        if oauth.get("clientSecretVersion"):
            self.add_secret_version(
                oauth["clientSecretVersion"],
                self._ev(
                    rel,
                    oauth["clientSecretVersion"],
                    f"OAuth client secret CES uses for {owner}",
                ),
            )
        sa = (auth.get("serviceAccountAuthConfig") or {}).get("serviceAccount")
        if sa:
            self.graph.add(
                ids.SERVICE_ACCOUNT,
                ids.service_account(self.ctx, sa),
                self._ev(
                    rel,
                    sa,
                    f"CES calls {owner} with this service account's token",
                ),
                project=ids.service_account_project(self.ctx, sa),
                name=sa,
            )

    def endpoint_config(
        self, data: dict[str, Any], rel: str, owner: str
    ) -> None:
        directory = (data.get("serviceDirectoryConfig") or {}).get("service")
        if directory:
            self.add_name(
                directory,
                self._ev(
                    rel, directory, f"Service Directory service of {owner}"
                ),
            )
        self.auth(data.get("apiAuthentication"), rel, owner)

    def openapi(self, spec: dict[str, Any], rel: str, owner: str) -> None:
        schema_ref = str(spec.get("openApiSchema") or "")
        schema_path = safe_bundle_file(self.root, schema_ref)
        schema_rel = (
            str(schema_path.relative_to(self.root))
            if schema_path is not None
            else None
        )
        text = read_text(schema_path) if schema_path is not None else schema_ref
        try:
            schema = yaml.safe_load(text or "") or {}
        except yaml.YAMLError:
            schema = {}
            self.notes.append(
                f"{owner}: the OpenAPI schema is not valid YAML/JSON; its servers are not followed"
            )
        if not isinstance(schema, dict):
            schema = {}
        urls = [
            str(s.get("url"))
            for s in (schema.get("servers") or [])
            if isinstance(s, dict) and s.get("url")
        ]
        urls += [str(spec["url"])] if spec.get("url") else []
        for url in dict.fromkeys(urls):
            if url.startswith(("http://", "https://")) and "{" not in url:
                self.add_url(
                    url,
                    self._ev(schema_rel or rel, url, f"server URL of {owner}"),
                )
        self.endpoint_config(spec, rel, owner)

    def toolsets(self, env_data: dict[str, Any]) -> None:
        env_toolsets = (
            env_data.get("toolsets")
            if isinstance(env_data.get("toolsets"), dict)
            else {}
        )
        self._also = ("environment.json",)
        for path in sorted((self.root / "toolsets").glob("*/*.json")):
            rel = str(path.relative_to(self.root))
            raw = read_json(path)
            name = str(raw.get("displayName") or path.parent.name)
            data = overlay(
                raw,
                env_toolsets.get(name)
                or env_toolsets.get(path.parent.name)
                or {},
            )
            owner = f"toolset `{name}`"
            mcp = data.get("mcpToolset")
            if isinstance(mcp, dict):
                address = str(mcp.get("serverAddress") or "")
                if address.startswith(("http://", "https://")):
                    self.add_url(
                        address,
                        self._ev(rel, address, f"MCP server of {owner}"),
                    )
                self.endpoint_config(mcp, rel, owner)
            api = data.get("openApiToolset")
            if isinstance(api, dict):
                self.openapi(api, rel, owner)
            conn = (data.get("connectorToolset") or {}).get("connection")
            if conn:
                self.add_name(
                    conn,
                    self._ev(
                        rel,
                        conn,
                        f"Integration Connectors connection of {owner}",
                    ),
                )
        self._also = ()

    def tools(
        self, used: set[str] | None, env_data: dict[str, Any]
    ) -> set[str]:
        """Seed the tools in use; returns the tool folders that are not used."""
        env_tools = (
            env_data.get("tools")
            if isinstance(env_data.get("tools"), dict)
            else {}
        )
        skipped: set[str] = set()
        self._also = ("environment.json",)
        for path in sorted((self.root / "tools").glob("*/*.json")):
            rel = str(path.relative_to(self.root))
            raw = read_json(path)
            name = str(raw.get("displayName") or path.parent.name)
            if used is not None and not (
                {name, path.parent.name, str(raw.get("name") or "")} & used
            ):
                skipped.add(path.parent.name)
                self.unused_tools.append(name)
                continue
            data = overlay(
                raw,
                env_tools.get(name) or env_tools.get(path.parent.name) or {},
            )
            owner = f"tool `{name}`"
            ds_tool = data.get("dataStoreTool") or {}
            source = ds_tool.get("dataStoreSource") or {}
            store = source.get("dataStore")
            store_name = store.get("name") if isinstance(store, dict) else store
            if store_name and store_name != "$env_var":
                self.add_name(
                    ids.data_store(str(store_name)),
                    self._ev(
                        rel,
                        str(store_name),
                        f"Vertex AI Search data store that {owner} searches",
                    ),
                )
            engine_src = ds_tool.get("engineSource") or {}
            if engine_src.get("engine") and engine_src["engine"] != "$env_var":
                self.add_name(
                    str(engine_src["engine"]),
                    self._ev(
                        rel,
                        str(engine_src["engine"]),
                        f"Vertex AI Search engine that {owner} searches",
                    ),
                )
            for item in engine_src.get("dataStoreSources") or []:
                inner = (item or {}).get("dataStore") or {}
                inner_name = (
                    inner.get("name") if isinstance(inner, dict) else inner
                )
                if inner_name and inner_name != "$env_var":
                    self.add_name(
                        ids.data_store(str(inner_name)),
                        self._ev(
                            rel,
                            str(inner_name),
                            f"data store that {owner} searches",
                        ),
                    )
            if isinstance(data.get("openApiTool"), dict):
                self.openapi(data["openApiTool"], rel, owner)
            mcp_tool = data.get("mcpTool")
            if isinstance(mcp_tool, dict):
                if str(mcp_tool.get("serverAddress") or "").startswith("http"):
                    self.add_url(
                        mcp_tool["serverAddress"],
                        self._ev(
                            rel,
                            mcp_tool["serverAddress"],
                            f"MCP server of {owner}",
                        ),
                    )
                self.endpoint_config(mcp_tool, rel, owner)
            for key, label in (
                ("connectorTool", "Integration Connectors connection"),
                ("fileSearchTool", "RAG corpus"),
            ):
                value = (data.get(key) or {}).get(
                    "connection" if key == "connectorTool" else "fileCorpus"
                )
                if value and value != "$env_var":
                    self.add_name(
                        value, self._ev(rel, value, f"{label} of {owner}")
                    )
        self._also = ()
        return skipped

    # -- text scan ------------------------------------------------------------

    # -- app settings and text scan (seed_refs) ------------------------------

    def app_settings(
        self,
        app_data: dict[str, Any],
        env_data: dict[str, Any],
        app_id: str | None = None,
    ) -> None:
        """Logging dataset and buckets, DLP templates, certificate secrets, engines."""
        seed_refs.seed_app_settings(self, app_data, env_data, app_id)

    def text_refs(self, refs: Refs, skip_prefixes: tuple[str, ...]) -> None:
        """URLs, `gs://` paths, secrets, SQL tables in the files the agents run."""
        seed_refs.seed_text_refs(self, refs, skip_prefixes)
