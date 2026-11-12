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

"""Identities of the graph and the roles they hold (after the walk).

The CES service agent (CES calls the tools as it) and every service account
node: their project roles (project IAM policy) and their roles on the other
attached resources (each node's IAM). Also writes the resource folders.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport import ids
from cxas_scrapi.utils.passport.files import safe_folder
from cxas_scrapi.utils.passport.graph import READ
from cxas_scrapi.utils.passport.http import NotReadable
from cxas_scrapi.utils.passport.iam import (
    READ_ROLES,
    ces_service_agent_member,
    policy_bindings,
)
from cxas_scrapi.utils.passport.model import PASSPORT_DIR_NAME
from cxas_scrapi.utils.passport.plugins.base import render_readme

if TYPE_CHECKING:
    from cxas_scrapi.utils.passport.graph import ResourceGraph, WalkContext
    from cxas_scrapi.utils.passport.scrub import Writer


def assign_folders(graph: ResourceGraph) -> None:
    """`passport/<service>/<resource>/` for every node, unique."""
    used: set[str] = set()
    for node in graph.ordered():
        plugin = graph.plugin_for(node)
        folder = f"{plugin.folder_of(node)}/{safe_folder(plugin.resource_folder(node, graph.ctx))}"
        while folder in used:
            folder += "_"
        used.add(folder)
        node.folder = folder


def assign_roles(
    graph: ResourceGraph, ctx: WalkContext
) -> list[dict[str, Any]]:
    """Roles of the CES service agent and of each service account node."""
    policy = None
    if ctx.live and ctx.reader is not None and ctx.project_id:
        try:
            policy = ctx.reader.get_iam_policy(
                f"https://cloudresourcemanager.googleapis.com/v1/projects/{ctx.project_id}:getIamPolicy",
                area="project.iam",
                post=True,
            )
        except NotReadable as exc:
            ctx.read_failed(
                exc,
                kind="resourcemanager.project",
                rid=f"projects/{ctx.project_id}",
                what="project IAM policy",
                role=READ_ROLES["project.iam"],
                impact="the project roles of the identities are unknown",
            )
    project_bindings = policy_bindings(policy) if policy is not None else []
    identities: list[tuple[str, str, Any]] = []
    ces = ces_service_agent_member(ctx.project_number)
    if ces:
        identities.append(
            (
                ces,
                "CES service agent: CES calls the agent's tools and data stores and writes its logs as this identity",
                None,
            )
        )
    for node in graph.by_kind(ids.SERVICE_ACCOUNT):
        users = (
            ", ".join(
                sorted(
                    {
                        graph.plugin_for(n).label_of(n)
                        for n, _ in graph.dependents(node.ref)
                    }
                )
            )
            or "the agent"
        )
        identities.append(
            (
                f"serviceAccount:{node.ref.id.rsplit('/', 1)[-1]}",
                f"identity of {users}",
                node,
            )
        )
    seen_members = {m for m, _, _ in identities}
    for n in graph.ordered():
        for b in n.iam or []:
            if (
                b.member.startswith("serviceAccount:")
                and b.member not in seen_members
            ):
                seen_members.add(b.member)
                identities.append(
                    (
                        b.member,
                        f"service agent with access to {graph.plugin_for(n).label_of(n)}",
                        None,
                    )
                )
    out = []
    for member, label, node in identities:
        project_roles = (
            sorted(
                b.role + (f" (condition: {b.condition})" if b.condition else "")
                for b in project_bindings
                if b.member == member
            )
            if (node is not None or member == ces)
            else []
        )
        resource_roles = [
            {
                "kind": n.kind,
                "resource": n.ref.id,
                "folder": f"{PASSPORT_DIR_NAME}/{n.folder}",
                "role": b.role,
            }
            for n in graph.ordered()
            for b in n.iam or []
            if b.member == member
        ]
        if node is not None:
            node.extras["project_roles"] = project_roles
            node.extras["resource_roles"] = resource_roles
        out.append(
            {
                "member": member,
                "identity": label,
                "folder": f"{PASSPORT_DIR_NAME}/{node.folder}"
                if node is not None
                else None,
                "project_roles": project_roles if policy is not None else None,
                "roles_on_attached_resources": resource_roles,
            }
        )
    return out


def write_nodes(
    graph: ResourceGraph, writer: Writer, app_display_name: str
) -> None:
    """Write the actionable files of every node (plus a README when a read failed or ran offline)."""
    for node in graph.ordered():
        plugin = graph.plugin_for(node)
        files = plugin.files(node, graph.ctx) if node.status == READ else {}
        purposes: dict[str, str] = {}
        for name, (content, purpose) in files.items():
            writer.text(
                f"{PASSPORT_DIR_NAME}/{node.folder}/{name}", content, purpose
            )
            purposes[name] = purpose
        if node.status != READ or graph.failures_of(node.ref):
            writer.text(
                f"{PASSPORT_DIR_NAME}/{node.folder}/README.md",
                render_readme(plugin, node, graph, purposes, app_display_name),
                "what it is, why the agent needs it, its live settings and IAM",
            )
