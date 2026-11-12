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

"""Service accounts the attached resources run as, and the roles they hold.

Roles come from the project IAM policy and from the IAM of the other attached
resources (filled in after the walk by `identities.assign_roles`); the walk
never follows a service account to what else it could reach.
"""

from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport import ids
from cxas_scrapi.utils.passport.http import NotReadable
from cxas_scrapi.utils.passport.iam import READ_ROLES
from cxas_scrapi.utils.passport.plugins.base import Plugin

if TYPE_CHECKING:
    from cxas_scrapi.utils.passport.graph import Node, WalkContext

API = "https://iam.googleapis.com/v1"


def email_of(node: Node) -> str:
    return node.ref.id.rsplit("/", 1)[-1]


class ServiceAccountPlugin(Plugin):
    kind = ids.SERVICE_ACCOUNT
    service = "IAM"
    noun = "service account"
    folder = "iam"

    def fetch(self, node: Node, ctx: WalkContext) -> None:
        email = urllib.parse.quote(email_of(node), safe="@")
        project = node.ref.id.split("/")[1]
        node.config = ctx.reader.get(
            f"{API}/projects/{project}/serviceAccounts/{email}", area=self.kind
        )
        try:
            keys = ctx.reader.get(
                f"{API}/projects/{project}/serviceAccounts/{email}/keys?keyTypes=USER_MANAGED",
                area=self.kind,
            )
            node.extras["user_managed_keys"] = len(keys.get("keys") or [])
        except NotReadable as exc:
            ctx.read_failed(
                exc,
                kind="iam.serviceAccountKeys",
                rid=f"{node.ref.id}/keys",
                what="user-managed key list",
                role=READ_ROLES[self.kind],
                owner=node.ref,
            )

    def resource_folder(self, node: Node, ctx: WalkContext) -> str:
        email = email_of(node)
        local, _, domain = email.partition("@")
        project = ids.service_account_project(ctx, email)
        if ctx.is_source(project) and domain.endswith(
            ".iam.gserviceaccount.com"
        ):
            return local
        return email

    def label_of(self, node: Node) -> str:
        return f"service account `{email_of(node)}`"

    def facts(self, node: Node) -> list[tuple[str, Any]]:
        cfg = node.config
        return [
            ("Email", email_of(node)),
            ("Display name", cfg.get("displayName")),
            ("Description", cfg.get("description")),
            ("Disabled", cfg.get("disabled", False) if cfg else None),
            ("User-managed keys", node.extras.get("user_managed_keys")),
            ("Project roles", node.extras.get("project_roles")),
            (
                "Roles on attached resources",
                [
                    f"{r['role']} on {r['kind']} {r['resource']}"
                    for r in node.extras.get("resource_roles", [])
                ],
            ),
        ]
