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

"""API Gateway: the gateway an agent URL (`*.gateway.dev`) points at, and its API config.

Gateway: its live config; edge: the API config it serves. API config: its live
config (view FULL) with the OpenAPI documents and service configs decoded into
files; edges: the service account the gateway calls backends as, and the
backends of its `x-google-backend` addresses (Cloud Run services, Cloud
Functions, ...), classified like any URL of the agent.
"""

from __future__ import annotations

import base64
import binascii
import copy
from typing import TYPE_CHECKING, Any

import yaml

from cxas_scrapi.utils.passport import ids
from cxas_scrapi.utils.passport.files import safe_folder
from cxas_scrapi.utils.passport.graph import Edge
from cxas_scrapi.utils.passport.plugins.base import Plugin, dump_json
from cxas_scrapi.utils.passport.urls import classify_url

if TYPE_CHECKING:
    from cxas_scrapi.utils.passport.graph import Node, WalkContext

API = "https://apigateway.googleapis.com/v1"


def backend_addresses(text: str) -> list[str]:
    """`x-google-backend.address` values anywhere in an OpenAPI document."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    found: list[str] = []
    stack: list[Any] = [doc]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            backend = item.get("x-google-backend")
            if isinstance(backend, dict) and backend.get("address"):
                found.append(str(backend["address"]))
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return sorted(set(found))


def _decode_files(config: dict[str, Any], notes: list[str]) -> dict[str, str]:
    """Pop the base64 file contents out of an API config; {path: text}."""
    files: dict[str, str] = {}

    def take(item: Any) -> None:
        if not isinstance(item, dict) or item.get("contents") is None:
            return
        path = str(item.get("path") or f"file_{len(files) + 1}")
        raw = item.pop("contents")
        try:
            files[path] = base64.b64decode(raw).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            notes.append(f"`{path}` is not UTF-8 text: not exported.")

    for doc in config.get("openapiDocuments") or []:
        take((doc or {}).get("document"))
    for item in config.get("managedServiceConfigs") or []:
        take(item)
    for grpc in config.get("grpcServices") or []:
        descriptor = (grpc or {}).get("fileDescriptorSet")
        if isinstance(descriptor, dict) and descriptor.pop("contents", None):
            notes.append(
                "The gRPC file descriptor set is binary: not exported."
            )
        for source in (grpc or {}).get("source") or []:
            take(source)
    return files


class GatewayPlugin(Plugin):
    kind = ids.GATEWAY
    service = "API Gateway"
    noun = "gateway"
    folder = "api_gateway"

    def fetch(self, node: Node, ctx: WalkContext) -> None:
        node.config = ctx.reader.get(f"{API}/{node.ref.id}", area=self.kind)
        node.location = node.ref.id.split("/")[3]

    def edges(self, node: Node, ctx: WalkContext) -> list[Edge]:
        # projects/<p>/locations/global/apis/<api>/configs/<config>
        parts = str(node.config.get("apiConfig") or "").split("/")
        if len(parts) != 8:
            return []
        project = ctx.project_key(parts[1])
        return [
            Edge(
                ids.API_CONFIG,
                "/".join(["projects", str(project), *parts[2:]]),
                "serves this API config",
                project=project,
                location=parts[3],
                name=parts[7],
            )
        ]

    def files(self, node: Node, ctx: WalkContext) -> dict[str, tuple[str, str]]:
        return {"gateway.json": (dump_json(node.config), "live gateway config")}

    def facts(self, node: Node) -> list[tuple[str, Any]]:
        cfg = node.config
        return [
            ("Default hostname", cfg.get("defaultHostname")),
            ("URLs the agent calls", node.hints.get("urls") or []),
            ("API config", cfg.get("apiConfig")),
            ("State", cfg.get("state")),
            ("Display name", cfg.get("displayName")),
            ("Labels", cfg.get("labels")),
        ]


class ApiConfigPlugin(Plugin):
    kind = ids.API_CONFIG
    service = "API Gateway"
    noun = "API config"
    folder = "api_gateway"

    def fetch(self, node: Node, ctx: WalkContext) -> None:
        config = copy.deepcopy(
            ctx.reader.get(f"{API}/{node.ref.id}?view=FULL", area=self.kind)
        )
        documents = _decode_files(config, node.notes)
        node.config = config
        node.location = node.ref.id.split("/")[3]
        node.extras["documents"] = documents
        node.extras["backends"] = sorted(
            {a for text in documents.values() for a in backend_addresses(text)}
        )

    def edges(self, node: Node, ctx: WalkContext) -> list[Edge]:
        out: list[Edge] = []
        account = str(node.config.get("gatewayServiceAccount") or "")
        email = account.rsplit("/", 1)[-1]
        if "@" in email:
            out.append(
                Edge(
                    ids.SERVICE_ACCOUNT,
                    ids.service_account(ctx, email),
                    "the gateway calls its backends as this service account",
                    project=ids.service_account_project(ctx, email),
                    name=email,
                )
            )
        for address in node.extras.get("backends") or []:
            if not address.startswith(("http://", "https://")):
                continue
            target = classify_url(address, ctx)
            out.append(
                Edge(
                    target.kind,
                    target.id,
                    "backend of the API (x-google-backend address)",
                    project=target.project,
                    location=target.location,
                    name=target.name,
                    hints=target.hints,
                )
            )
        return out

    def resource_folder(self, node: Node, ctx: WalkContext) -> str:
        parts = node.ref.id.split("/")
        return f"{parts[5]}.{parts[7]}" if len(parts) == 8 else node.name

    def files(self, node: Node, ctx: WalkContext) -> dict[str, tuple[str, str]]:
        out = {
            "api_config.json": (
                dump_json(node.config),
                "live API config (the file contents are in files/)",
            )
        }
        for path, text in sorted((node.extras.get("documents") or {}).items()):
            out[f"files/{safe_folder(path)}"] = (
                text if text.endswith("\n") else text + "\n",
                "OpenAPI document or service config of the API config",
            )
        return out

    def facts(self, node: Node) -> list[tuple[str, Any]]:
        cfg = node.config
        return [
            ("Display name", cfg.get("displayName")),
            ("State", cfg.get("state")),
            ("Gateway service account", cfg.get("gatewayServiceAccount")),
            ("Service config ID", cfg.get("serviceConfigId")),
            ("Files", sorted(node.extras.get("documents") or {})),
            ("Backends", node.extras.get("backends") or []),
        ]
