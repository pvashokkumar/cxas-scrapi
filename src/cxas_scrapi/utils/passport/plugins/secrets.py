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

"""Secret Manager secrets: name and settings, who may read them. Never values.

The one payload a pull reads is an MCP Toolbox config mounted by a Cloud Run
service; it is exported redacted with that service (`cloud_run/<svc>/tools.yaml`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport.http import NotReadable
from cxas_scrapi.utils.passport.iam import (
    IAM_POLICY_ROLES,
    policy_bindings,
    visible,
)
from cxas_scrapi.utils.passport.plugins.base import Plugin

if TYPE_CHECKING:
    from cxas_scrapi.utils.passport.graph import Node, WalkContext

API = "https://secretmanager.googleapis.com/v1"
_VALUE_READER_ROLES = (
    "roles/secretmanager.secretAccessor",
    "roles/owner",
    "roles/editor",
)


class SecretPlugin(Plugin):
    kind = "secretmanager.secret"
    service = "Secret Manager"
    noun = "secret"
    folder = "secret_manager"

    def fetch(self, node: Node, ctx: WalkContext) -> None:
        node.config = ctx.reader.get(f"{API}/{node.ref.id}", area=self.kind)
        try:
            node.iam = policy_bindings(
                ctx.reader.get_iam_policy(
                    f"{API}/{node.ref.id}:getIamPolicy", area=self.kind
                )
            )
        except NotReadable as exc:
            ctx.read_failed(
                exc,
                kind=self.kind,
                rid=node.ref.id,
                what="IAM policy (who may read the value)",
                role=IAM_POLICY_ROLES[self.kind],
                owner=node.ref,
            )

    def resource_folder(self, node: Node, ctx: WalkContext) -> str:
        project, name = node.ref.id.split("/")[1], node.ref.id.split("/")[3]
        return name if ctx.is_source(project) else f"{project}.{name}"

    def facts(self, node: Node) -> list[tuple[str, Any]]:
        cfg = node.config
        replication = cfg.get("replication") or {}
        shown, hidden = visible(
            [b for b in node.iam or [] if b.role in _VALUE_READER_ROLES]
        )
        readers = sorted({b.member for b in shown})
        if hidden:
            readers.append(f"{hidden} person/group binding(s), not named")
        return [
            (
                "Replication",
                "automatic"
                if "automatic" in replication
                else (
                    "user-managed: "
                    + ", ".join(
                        str(r.get("location"))
                        for r in (replication.get("userManaged") or {}).get(
                            "replicas"
                        )
                        or []
                    )
                    if replication
                    else None
                ),
            ),
            ("Labels", cfg.get("labels")),
            ("Rotation", cfg.get("rotation")),
            (
                "Notification topics",
                [t.get("name") for t in cfg.get("topics") or []],
            ),
            ("Version aliases", cfg.get("versionAliases")),
            ("Expires", cfg.get("expireTime")),
            ("May read the value (secretAccessor)", readers),
        ]
