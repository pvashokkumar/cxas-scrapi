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

"""Usage-scoped graph of the Google Cloud resources a CES agent depends on.

Nodes enter the graph only with evidence of use: a reference in the agent
files (seed) or a runtime dependency in the live config of another node (an
edge: the identity a service runs as, a secret it mounts, the datasets its SQL
reads, ...). Nothing is added because an identity *could* reach it. Each node
is read once by the plugin of its kind; a node whose usage scope grows later
(another table of a dataset, another object of a bucket) gets its scope
details read again. A read that fails makes the node `not_readable`; a failed
read of part of a node (a table schema, an IAM policy, the MCP server config)
or of the project is a `ReadFailure`. Both are listed as not readable and the
walk goes on.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport.http import NotReadable

if TYPE_CHECKING:
    from cxas_scrapi.utils.passport.iam import Binding
    from cxas_scrapi.utils.passport.plugins.base import Plugin

# Node status values.
PENDING, READ, NOT_READABLE, OFFLINE, EXTERNAL = (
    "pending",
    "read",
    "not_readable",
    "not_read_offline",
    "external",
)


@dataclass(frozen=True)
class NodeRef:
    kind: str  # e.g. "bigquery.dataset"
    id: str  # full resource name with raw values, e.g. "projects/p/datasets/d"


@dataclass(frozen=True)
class Evidence:
    """Why a node is in the graph: a file and line, or a parent node."""

    text: str
    file: str | None = None
    line: int | None = None
    parent: NodeRef | None = None
    relation: str | None = None


@dataclass
class Edge:
    """A dependency a plugin found in the live config of a node."""

    kind: str
    id: str
    relation: str
    project: str | None = None
    location: str | None = None
    name: str | None = None
    scope: tuple[str, ...] = ()
    whole: bool = False
    purpose: str | None = None
    hints: dict[str, Any] = field(default_factory=dict)


@dataclass
class Node:
    ref: NodeRef
    project: str | None = None
    location: str | None = None
    name: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    scope: set[str] = field(default_factory=set)  # tables, objects, ... in use
    whole: bool = False  # the agent uses all of it
    purposes: list[str] = field(default_factory=list)
    hints: dict[str, Any] = field(default_factory=dict)
    status: str = PENDING
    config: dict[str, Any] = field(default_factory=dict)
    extras: dict[str, Any] = field(default_factory=dict)
    iam: list[Binding] | None = None  # None: no IAM policy read
    depends_on: list[tuple[NodeRef, str]] = field(default_factory=list)
    error: str | None = None
    error_category: str | None = None
    missing_permission: str | None = None
    notes: list[str] = field(default_factory=list)
    folder: str = ""
    scope_done: set[str] = field(default_factory=set)
    whole_done: bool = False

    @property
    def kind(self) -> str:
        return self.ref.kind

    @property
    def scope_dirty(self) -> bool:
        return (self.whole and not self.whole_done) or bool(
            self.scope - self.scope_done
        )

    def mark_not_readable(self, exc: NotReadable, role: str | None) -> None:
        self.status = NOT_READABLE
        self.error = str(exc)
        self.error_category = exc.category
        self.missing_permission = missing_permission_text(exc, role)


def missing_permission_text(exc: NotReadable, role: str | None) -> str | None:
    """What would make the read work, from the error and the kind's read role."""
    category = exc.category
    if category == "api_disabled":
        api = exc.service or "the API"
        return f"{api} is disabled in the project (the pull never enables APIs)"
    if category == "not_found":
        return "none: the resource was deleted or renamed"
    if category == "permission_denied":
        parts = [p for p in (role, exc.permission) if p]
        if role and exc.permission:
            return f"{role} (permission {exc.permission})"
        return parts[0] if parts else "a role that can read it"
    return None


@dataclass(frozen=True)
class ReadFailure:
    """A failed read of part of a resource, or of the source project itself.

    Listed with the resources that could not be read (manifest `not_readable`,
    the top of PLACEHOLDERS.md, the `cxas pull` summary); `--strict` fails on
    it as on a resource that could not be read at all.
    """

    kind: str  # what was read, e.g. "bigquery.table", "secretmanager.payload"
    id: str  # its resource name (raw values)
    what: str  # e.g. "schema of table `orders`"
    error: str
    category: str
    missing_permission: str | None
    owner: NodeRef | None = None  # node it belongs to; None: the project
    impact: str | None = None  # what the bundle lacks because of it


@dataclass
class WalkContext:
    """What every plugin needs: the reader and the source project identity."""

    reader: Any
    project_id: str | None
    project_number: str | None
    live: bool
    errors: list[str] = field(default_factory=list)  # warnings, not reads
    failures: list[ReadFailure] = field(default_factory=list)
    cache: dict[str, Any] = field(default_factory=dict)
    timings_ms: dict[str, float] = field(default_factory=dict)

    def is_source(self, project: str | None) -> bool:
        return bool(project) and project in {
            self.project_id,
            self.project_number,
        }

    def project_key(self, project: str | None) -> str | None:
        """The source project ID for the source number; other values as given."""
        if project and project == self.project_number and self.project_id:
            return self.project_id
        return project or self.project_id

    def read_failed(
        self,
        exc: NotReadable,
        *,
        kind: str,
        rid: str,
        what: str,
        role: str | None,
        owner: NodeRef | None = None,
        impact: str | None = None,
    ) -> ReadFailure:
        """Record a failed read of part of a resource (`owner`) or of the project."""
        failure = ReadFailure(
            kind=kind,
            id=rid,
            what=what,
            error=str(exc),
            category=exc.category,
            missing_permission=missing_permission_text(exc, role),
            owner=owner,
            impact=impact,
        )
        known = {(f.kind, f.id, f.what) for f in self.failures}
        if (kind, rid, what) not in known:
            self.failures.append(failure)
        return failure


class ResourceGraph:
    """Nodes keyed by NodeRef, expanded by the plugin of each kind."""

    def __init__(
        self, ctx: WalkContext, plugins: dict[str, Plugin], fallback: Plugin
    ) -> None:
        self.ctx = ctx
        self.plugins = plugins
        self.fallback = fallback
        self.nodes: dict[NodeRef, Node] = {}
        self._queue: deque[NodeRef] = deque()

    def plugin_for(self, node: Node) -> Plugin:
        return self.plugins.get(node.kind, self.fallback)

    def add(
        self,
        kind: str,
        rid: str,
        evidence: Evidence,
        *,
        project: str | None = None,
        location: str | None = None,
        name: str | None = None,
        scope: tuple[str, ...] | list[str] = (),
        whole: bool = False,
        purpose: str | None = None,
        hints: dict[str, Any] | None = None,
    ) -> Node:
        """Add a node (or more evidence and scope to an existing one)."""
        ref = NodeRef(kind, rid)
        node = self.nodes.get(ref)
        if node is None:
            node = Node(
                ref=ref,
                project=project,
                location=location,
                name=name or rid.rsplit("/", 1)[-1],
            )
            self.nodes[ref] = node
            self._queue.append(ref)
        if evidence not in node.evidence:
            node.evidence.append(evidence)
        if location and not node.location:
            node.location = location
        before = node.scope_dirty
        node.scope.update(s for s in scope if s)
        node.whole = node.whole or whole
        if purpose and purpose not in node.purposes:
            node.purposes.append(purpose)
        for key, value in (hints or {}).items():
            if isinstance(value, list):
                bucket = node.hints.setdefault(key, [])
                bucket.extend(v for v in value if v not in bucket)
            else:
                node.hints.setdefault(key, value)
        if node.scope_dirty and not before and node.status != PENDING:
            self._queue.append(ref)
        return node

    def expand(self) -> None:
        """Read every node and follow its edges until nothing new appears."""
        while self._queue:
            node = self.nodes[self._queue.popleft()]
            plugin = self.plugin_for(node)
            started = time.perf_counter()
            try:
                self._process(node, plugin)
            finally:
                area = plugin.timing_area
                self.ctx.timings_ms[area] = round(
                    self.ctx.timings_ms.get(area, 0.0)
                    + (time.perf_counter() - started) * 1000.0,
                    3,
                )

    def _process(self, node: Node, plugin: Plugin) -> None:
        if node.status == PENDING:
            if not plugin.can_read(node):
                node.status = EXTERNAL
            elif not self.ctx.live or self.ctx.reader is None:
                node.status = OFFLINE
            else:
                try:
                    plugin.fetch(node, self.ctx)
                    node.status = READ
                except NotReadable as exc:
                    node.mark_not_readable(exc, plugin.read_role_of(node))
        if node.status != READ:
            return
        if node.scope_dirty:
            plugin.details(node, self.ctx)
            node.scope_done |= node.scope
            node.whole_done = node.whole_done or node.whole
        for edge in plugin.edges(node, self.ctx):
            target = NodeRef(edge.kind, edge.id)
            if target == node.ref:
                continue
            if (target, edge.relation) not in node.depends_on:
                node.depends_on.append((target, edge.relation))
            self.add(
                edge.kind,
                edge.id,
                Evidence(
                    text=f"{plugin.label_of(node)}: {edge.relation}",
                    parent=node.ref,
                    relation=edge.relation,
                ),
                project=edge.project,
                location=edge.location,
                name=edge.name,
                scope=edge.scope,
                whole=edge.whole,
                purpose=edge.purpose,
                hints=edge.hints,
            )

    def by_kind(self, kind: str) -> list[Node]:
        return sorted(
            (n for n in self.nodes.values() if n.kind == kind),
            key=lambda n: n.ref.id,
        )

    def ordered(self) -> list[Node]:
        """Nodes by plugin order, then id (stable output)."""
        order = {k: i for i, k in enumerate(self.plugins)}
        return sorted(
            self.nodes.values(),
            key=lambda n: (order.get(n.kind, len(order)), n.kind, n.ref.id),
        )

    def dependents(self, ref: NodeRef) -> list[tuple[Node, str]]:
        """Nodes that depend on `ref`, with the relation."""
        out = []
        for node in self.ordered():
            for target, relation in node.depends_on:
                if target == ref:
                    out.append((node, relation))
        return out

    def failures_of(self, ref: NodeRef) -> list[ReadFailure]:
        """Failed reads of parts of the node `ref` (a table, its IAM policy, ...)."""
        return [f for f in self.ctx.failures if f.owner == ref]

    def has_unreadable(self) -> bool:
        """A resource, a part of one or a project read failed (`--strict` fails)."""
        return bool(self.ctx.failures) or any(
            n.status == NOT_READABLE for n in self.nodes.values()
        )
