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

"""Runtime dependencies of a Cloud Run service, read from its live config.

Usage scope: a dataset is in use when the MCP config allows it or a tool's
SQL reads it; its tables are the ones that SQL names (all of them when a tool
can run any SQL). A bucket is in use when an MCP source allows it or the
service mounts it.
"""

from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport import ids
from cxas_scrapi.utils.passport.graph import Edge
from cxas_scrapi.utils.passport.mcp_config import (
    BQ_SOURCE_KINDS,
    GCS_SOURCE_KINDS,
    GENERIC_BQ_TOOL_KINDS,
)
from cxas_scrapi.utils.passport.scan import sql_table_refs

if TYPE_CHECKING:
    from cxas_scrapi.utils.passport.graph import Node, WalkContext
    from cxas_scrapi.utils.passport.model import McpConfig, RunService


def identity_edge(
    ctx: WalkContext, email: str | None, project_number: str | None
) -> Edge | None:
    """The service account a workload runs as (the default compute SA if unset)."""
    email = email or ids.default_compute_sa(project_number)
    if not email:
        return None
    relation = "runs as service account" + (
        " (the project's default compute service account)"
        if email.endswith("-compute@developer.gserviceaccount.com")
        else ""
    )
    return Edge(
        ids.SERVICE_ACCOUNT,
        ids.service_account(ctx, email),
        relation,
        project=ids.service_account_project(ctx, email),
        name=email,
    )


def _project_number_of(ctx: WalkContext, project: str) -> str | None:
    if ctx.is_source(project):
        return ctx.project_number
    return project if project.isdigit() else None


def service_edges(node: Node, ctx: WalkContext) -> list[Edge]:
    project, region, _name = (
        node.ref.id.split("/")[1],
        node.ref.id.split("/")[3],
        node.ref.id.split("/")[5],
    )
    svc: RunService = node.extras["svc"]
    out: list[Edge] = []
    ident = identity_edge(
        ctx, svc.service_account, _project_number_of(ctx, project)
    )
    if ident:
        out.append(ident)
    mcp_secret = node.extras.get("mcp_secret")
    for env in svc.env:
        if env.get("secret"):
            out.append(
                Edge(
                    ids.SECRET,
                    ids.secret(
                        ctx, env.get("secret_project") or project, env["secret"]
                    ),
                    f"environment variable `{env['name']}` comes from this secret",
                    project=ctx.project_key(
                        env.get("secret_project") or project
                    ),
                )
            )
    for vol in svc.secret_volumes:
        if not vol["mounted"]:
            continue
        sid = ids.secret(
            ctx, vol.get("secret_project") or project, vol["secret"]
        )
        what = (
            " (the MCP server config, exported as tools.yaml)"
            if mcp_secret and mcp_secret[1] == vol["secret"]
            else ""
        )
        out.append(
            Edge(
                ids.SECRET,
                sid,
                f"mounted as a file at {', '.join(vol['mount_paths'])}{what}",
                project=ctx.project_key(vol.get("secret_project") or project),
            )
        )
    mcp: McpConfig | None = node.extras.get("mcp")
    if mcp is not None:
        out += mcp_source_edges(ctx, mcp, project)
    out += _annotation_edges(node, ctx, project, region)
    repo = ids.repository_of_image(ctx, svc.image)
    if (
        repo
        and ctx.is_source(repo[2])
        and not repo[0].endswith("/repositories/gcf-artifacts")
    ):
        out.append(
            Edge(
                ids.REPOSITORY,
                repo[0],
                "container image comes from this repository",
                project=repo[2],
                location=repo[1],
                hints={"images": [svc.image]},
            )
        )
    function_id = node.extras.get("function_id")
    if (
        function_id
        and (node.extras.get("labels") or {}).get("goog-managed-by")
        == "cloudfunctions"
    ):
        out.append(
            Edge(
                ids.FUNCTION,
                ids.function(ctx, project, region, function_id),
                "deployed and managed by this Cloud Function (gen2)",
                project=ctx.project_key(project),
                location=region,
            )
        )
    return out


def _annotation_edges(
    node: Node, ctx: WalkContext, project: str, region: str
) -> list[Edge]:
    template = (node.config.get("spec") or {}).get("template") or {}
    annotations = ((template.get("metadata") or {}).get("annotations")) or {}
    out: list[Edge] = []
    for entry in str(
        annotations.get("run.googleapis.com/cloudsql-instances") or ""
    ).split(","):
        parts = entry.strip().split(":")
        if len(parts) == 3:
            out.append(
                Edge(
                    "sqladmin.instance",
                    f"projects/{ctx.project_key(parts[0])}/instances/{parts[2]}",
                    "connects to this Cloud SQL instance",
                    project=ctx.project_key(parts[0]),
                    location=parts[1],
                )
            )
    connector = str(
        annotations.get("run.googleapis.com/vpc-access-connector") or ""
    )
    if connector:
        cid = (
            connector
            if connector.startswith("projects/")
            else f"projects/{ctx.project_key(project)}/locations/{region}/connectors/{connector}"
        )
        out.append(
            Edge(
                "vpcaccess.connector",
                cid,
                "sends traffic through this Serverless VPC Access connector",
            )
        )
    tspec = template.get("spec") or {}
    for volume in tspec.get("volumes") or []:
        csi = volume.get("csi") or {}
        bucket = (csi.get("volumeAttributes") or {}).get("bucketName")
        if csi.get("driver") == "gcsfuse.run.googleapis.com" and bucket:
            out.append(
                Edge(
                    ids.BUCKET,
                    ids.bucket(bucket),
                    "mounted as a volume (Cloud Storage FUSE)",
                    name=bucket,
                    whole=True,
                )
            )
    return out


def mcp_source_edges(
    ctx: WalkContext, mcp: McpConfig, project: str
) -> list[Edge]:
    """Datasets, buckets and databases the MCP server's sources and tools use."""
    out: list[Edge] = []
    for sname, src in sorted(mcp.sources.items()):
        kind = str(src.get("kind") or "").lower()
        src_project = str(src.get("project") or project)
        tools = {n: t for n, t in mcp.tools.items() if t.get("source") == sname}
        if kind in BQ_SOURCE_KINDS:
            generic = any(
                str(t.get("kind") or "").startswith(GENERIC_BQ_TOOL_KINDS)
                for t in tools.values()
            )
            for entry in src.get("allowedDatasets") or []:
                proj, _, dataset = str(entry).rpartition(".")
                out.append(
                    Edge(
                        ids.BQ,
                        ids.dataset(ctx, proj or src_project, dataset),
                        f"MCP source `{sname}` allows it (allowedDatasets)"
                        + ("; a tool can run any SQL on it" if generic else ""),
                        project=ctx.project_key(proj or src_project),
                        name=dataset,
                        whole=generic,
                    )
                )
            for tname, tool in sorted(tools.items()):
                for ref_proj, dataset, table in sql_table_refs(
                    str(tool.get("statement") or "")
                ):
                    out.append(
                        Edge(
                            ids.BQ,
                            ids.dataset(ctx, ref_proj or src_project, dataset),
                            f"MCP tool `{tname}` reads it",
                            project=ctx.project_key(ref_proj or src_project),
                            name=dataset,
                            scope=(table,),
                        )
                    )
        elif kind in GCS_SOURCE_KINDS:
            for bucket in src.get("allowedBuckets") or []:
                out.append(
                    Edge(
                        ids.BUCKET,
                        ids.bucket(str(bucket)),
                        f"MCP source `{sname}` reads it (allowedBuckets)",
                        name=str(bucket),
                        whole=True,
                    )
                )
        else:
            edge = _database_edge(ctx, sname, kind, src, src_project)
            if edge:
                out.append(edge)
    return out


def _database_edge(
    ctx: WalkContext, sname: str, kind: str, src: dict[str, Any], project: str
) -> Edge | None:
    relation = f"MCP source `{sname}` ({kind}) connects to it"
    p = ctx.project_key(project)
    if kind.startswith("cloud-sql") and src.get("instance"):
        return Edge(
            "sqladmin.instance",
            f"projects/{p}/instances/{src['instance']}",
            relation,
            project=p,
            location=src.get("region"),
        )
    if kind.startswith("alloydb") and src.get("cluster"):
        inst = f"/instances/{src['instance']}" if src.get("instance") else ""
        return Edge(
            "alloydb.instance" if inst else "alloydb.cluster",
            f"projects/{p}/locations/{src.get('region')}/clusters/{src['cluster']}{inst}",
            relation,
            project=p,
        )
    if kind == "spanner" and src.get("instance") and src.get("database"):
        return Edge(
            "spanner.database",
            f"projects/{p}/instances/{src['instance']}/databases/{src['database']}",
            relation,
            project=p,
        )
    if kind == "firestore":
        return Edge(
            "firestore.database",
            f"projects/{p}/databases/{src.get('database') or '(default)'}",
            relation,
            project=p,
        )
    if kind == "bigtable" and src.get("instance"):
        return Edge(
            "bigtable.instance",
            f"projects/{p}/instances/{src['instance']}",
            relation,
            project=p,
        )
    host = str(
        src.get("host") or src.get("baseUrl") or src.get("url") or ""
    ).strip()
    if host:
        netloc = (
            urllib.parse.urlsplit(
                host if "://" in host else f"//{host}"
            ).hostname
            or host
        )
        return Edge(ids.ENDPOINT, f"https://{netloc}", relation, name=netloc)
    return None
