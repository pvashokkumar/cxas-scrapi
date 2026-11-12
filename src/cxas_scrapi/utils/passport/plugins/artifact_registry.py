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

"""Artifact Registry repositories that hold the images the attached services run."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport import ids
from cxas_scrapi.utils.passport.plugins.base import Plugin, dump_json

if TYPE_CHECKING:
    from cxas_scrapi.utils.passport.graph import Node, WalkContext


class ArtifactRepositoryPlugin(Plugin):
    kind = ids.REPOSITORY
    service = "Artifact Registry"
    noun = "repository"
    folder = "artifact_registry"

    def fetch(self, node: Node, ctx: WalkContext) -> None:
        node.config = ctx.reader.get(
            f"https://artifactregistry.googleapis.com/v1/{node.ref.id}",
            area=self.kind,
        )
        node.location = node.ref.id.split("/")[3]

    def files(self, node: Node, ctx: WalkContext) -> dict[str, tuple[str, str]]:
        return {
            "repository.json": (
                dump_json(node.config),
                "live repository settings",
            )
        }

    def facts(self, node: Node) -> list[tuple[str, Any]]:
        cfg = node.config
        return [
            ("Format", cfg.get("format")),
            ("Mode", cfg.get("mode")),
            ("Registry URI", cfg.get("registryUri")),
            ("Images in use", node.hints.get("images")),
            (
                "Cleanup policies",
                sorted((cfg.get("cleanupPolicies") or {}).keys()) or None,
            ),
            (
                "Immutable tags",
                (cfg.get("dockerConfig") or {}).get("immutableTags"),
            ),
            ("Labels", cfg.get("labels")),
        ]
