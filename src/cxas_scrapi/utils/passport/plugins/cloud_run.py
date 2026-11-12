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

"""Cloud Run services: the live service config, who may invoke it, and the
MCP server config (tools.yaml) when the service is MCP Toolbox.

Edges: the service account it runs as, the secrets of its environment and
volumes, the data sources of its MCP config (datasets its tool SQL reads,
buckets it allows, Cloud SQL / Spanner / AlloyDB ...), Cloud SQL and VPC
connectors, the Artifact Registry repository of its image, and the Cloud
Function that deployed it (Cloud Functions gen2).
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Any

import yaml

from cxas_scrapi.utils.passport import run_edges
from cxas_scrapi.utils.passport.http import NotReadable
from cxas_scrapi.utils.passport.iam import (
    IAM_POLICY_ROLES,
    READ_ROLES,
    policy_bindings,
    visible,
)
from cxas_scrapi.utils.passport.mcp_config import (
    parse_mcp_config,
    redact_credentials,
)
from cxas_scrapi.utils.passport.model import McpConfig, RunService
from cxas_scrapi.utils.passport.plugins.base import Plugin
from cxas_scrapi.utils.passport.render import DoubleQuoted
from cxas_scrapi.utils.passport.run_spec import (
    apply_service_spec,
    find_mcp_config_file,
    redact_plain_env,
    sanitize_knative_service,
)

if TYPE_CHECKING:
    from cxas_scrapi.utils.passport.graph import Edge, Node, WalkContext


class _YamlDumper(yaml.SafeDumper):
    pass


_YamlDumper.add_representer(
    DoubleQuoted,
    lambda dumper, data: dumper.represent_scalar(
        "tag:yaml.org,2002:str", str(data), style='"'
    ),
)


def parse_run_id(rid: str) -> tuple[str, str, str]:
    """(project, region, service) of projects/p/locations/r/services/s."""
    parts = rid.split("/")
    return parts[1], parts[3], parts[5]


def _annotation(spec: dict[str, Any], key: str, template: bool = False) -> Any:
    meta = (
        ((spec.get("spec") or {}).get("template") or {}).get("metadata")
        if template
        else spec.get("metadata")
    ) or {}
    return (meta.get("annotations") or {}).get(key)


class CloudRunServicePlugin(Plugin):
    kind = "run.service"
    service = "Cloud Run"
    noun = "service"
    folder = "cloud_run"

    def fetch(self, node: Node, ctx: WalkContext) -> None:
        project, region, name = parse_run_id(node.ref.id)
        live = ctx.reader.get(
            f"https://{region}-run.googleapis.com/apis/serving.knative.dev/v1/"
            f"namespaces/{project}/services/{name}",
            area=self.kind,
        )
        raw_meta = live.get("metadata") or {}
        spec, notes = sanitize_knative_service(live)
        redactions = redact_plain_env(spec)
        svc = RunService(project=project, region=region, name=name, spec=spec)
        apply_service_spec(svc, spec)
        node.location = region
        node.config = spec
        node.notes += notes
        raw_urls = _json_list(
            (raw_meta.get("annotations") or {}).get("run.googleapis.com/urls")
        )
        clean_urls = [
            u for u in raw_urls if not u.endswith(".a.run.app")
        ] or raw_urls
        node.extras.update(
            svc=svc,
            urls=clean_urls,
            labels=dict(raw_meta.get("labels") or {}),
            function_id=(raw_meta.get("annotations") or {}).get(
                "cloudfunctions.googleapis.com/function-id"
            ),
        )
        if redactions:
            node.notes.append(
                "Credential-like environment values are not in the passport: "
                + ", ".join(f"`{r['key']}`" for r in redactions)
                + "."
            )
        try:
            node.iam = policy_bindings(
                ctx.reader.get_iam_policy(
                    f"https://run.googleapis.com/v2/projects/{project}/locations/"
                    f"{region}/services/{name}:getIamPolicy",
                    area=self.kind,
                )
            )
        except NotReadable as exc:
            ctx.read_failed(
                exc,
                kind=self.kind,
                rid=node.ref.id,
                what="IAM policy (who may invoke it)",
                role=IAM_POLICY_ROLES[self.kind],
                owner=node.ref,
            )
        self._read_mcp_config(node, ctx, svc, live)

    def _read_mcp_config(
        self, node: Node, ctx: WalkContext, svc: RunService, live: dict
    ) -> None:
        found = find_mcp_config_file(svc, live)
        if not found:
            return
        secret_project, secret, version, mount_file = found
        project = ctx.project_key(secret_project or svc.project)
        cfg = McpConfig(secret=secret, version=version, mount_file=mount_file)
        node.extras["mcp_secret"] = (project, secret, mount_file)
        payload = f"projects/{project}/secrets/{secret}/versions/{version or 'latest'}"
        try:
            data = ctx.reader.get(
                f"https://secretmanager.googleapis.com/v1/{payload}:access",
                area="secretmanager.payload",
            )
        except NotReadable as exc:
            ctx.read_failed(
                exc,
                kind="secretmanager.payload",
                rid=payload,
                what=f"MCP server config ({mount_file}) in secret `{secret}`",
                role=READ_ROLES["secretmanager.payload"],
                owner=node.ref,
                impact="its sources and tool SQL are unknown, so the datasets, buckets and databases the MCP server uses are missing from the bundle",
            )
            return
        raw = (data.get("payload") or {}).get("data")
        try:
            text = base64.b64decode(raw or "").decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return
        parsed = parse_mcp_config(text)
        if parsed is None:
            return  # a mounted secret that is not an MCP config: name only
        cfg.text = redact_credentials(text)
        cfg.sources, cfg.tools, cfg.toolsets = parsed
        node.extras["mcp"] = cfg

    def edges(self, node: Node, ctx: WalkContext) -> list[Edge]:
        return run_edges.service_edges(node, ctx)

    def files(self, node: Node, ctx: WalkContext) -> dict[str, tuple[str, str]]:
        if (
            node.extras.get("function_id")
            and (node.extras.get("labels") or {}).get("goog-managed-by")
            == "cloudfunctions"
        ):
            return {}
        _project, region, name = parse_run_id(node.ref.id)
        header = (
            f"# Cloud Run service `{name}` ({region}) as deployed in the source project,\n"
            "# read by `cxas pull --passport` (Knative serving.knative.dev/v1). Server-generated\n"
            "# fields are removed; credential-like environment values are redacted.\n"
        )
        out = {
            "service.yaml": (
                header
                + yaml.dump(
                    node.config,
                    Dumper=_YamlDumper,
                    sort_keys=True,  # maps come back in any order
                    default_flow_style=False,
                    width=100,
                ),
                "live service config",
            )
        }
        mcp = node.extras.get("mcp")
        if mcp is not None and mcp.text:
            out["tools.yaml"] = (
                mcp.text if mcp.text.endswith("\n") else mcp.text + "\n",
                f"MCP server config from secret `{mcp.secret}` (sources and tool SQL; credentials redacted)",
            )
        return out

    def facts(self, node: Node) -> list[tuple[str, Any]]:
        spec = node.config
        tspec = ((spec.get("spec") or {}).get("template") or {}).get(
            "spec"
        ) or {}
        containers = tspec.get("containers") or []
        first = containers[0] if containers else {}
        svc: RunService | None = node.extras.get("svc")
        shown, hidden = visible(
            [b for b in node.iam or [] if b.role == "roles/run.invoker"]
        )
        invokers = sorted(b.member for b in shown)
        if hidden:
            invokers.append(f"{hidden} person/group binding(s), not named")
        mcp = node.extras.get("mcp")
        env = [
            f"{e['name']} <- secret {e['secret']}"
            if e.get("secret")
            else f"{e['name']}={e.get('value', '')}"
            for e in (svc.env if svc else [])
        ]
        return [
            ("URLs", node.extras.get("urls") or []),
            ("URLs the agent calls", node.hints.get("urls") or []),
            ("Image", first.get("image")),
            ("Args", first.get("args")),
            (
                "Ports",
                [p.get("containerPort") for p in first.get("ports") or []],
            ),
            ("Environment", env),
            ("Service account", svc.service_account if svc else None),
            ("Ingress", _annotation(spec, "run.googleapis.com/ingress")),
            (
                "Invoker IAM check disabled",
                _annotation(spec, "run.googleapis.com/invoker-iam-disabled")
                == "true",
            ),
            ("May invoke it (roles/run.invoker)", invokers),
            (
                "Custom audiences",
                _annotation(spec, "run.googleapis.com/custom-audiences"),
            ),
            (
                "Min instances",
                _annotation(spec, "autoscaling.knative.dev/minScale", True),
            ),
            (
                "Max instances",
                _annotation(spec, "autoscaling.knative.dev/maxScale", True),
            ),
            ("Concurrency", tspec.get("containerConcurrency")),
            ("Timeout seconds", tspec.get("timeoutSeconds")),
            ("Limits", (first.get("resources") or {}).get("limits")),
            (
                "VPC connector",
                _annotation(
                    spec, "run.googleapis.com/vpc-access-connector", True
                ),
            ),
            (
                "Cloud SQL instances",
                _annotation(
                    spec, "run.googleapis.com/cloudsql-instances", True
                ),
            ),
            ("Deployed by Cloud Function", node.extras.get("function_id")),
            ("MCP config secret", mcp.secret if mcp else None),
            (
                "MCP sources",
                [
                    f"{n} ({s.get('kind')})"
                    for n, s in sorted(mcp.sources.items())
                ]
                if mcp
                else None,
            ),
            ("MCP tools", sorted(mcp.tools) if mcp else None),
        ]

    def summary(self, node: Node) -> dict[str, Any]:
        _project, region, name = parse_run_id(node.ref.id)
        out: dict[str, Any] = {"service": name, "region": region}
        out.update(super().summary(node))
        return out


def _json_list(raw: Any) -> list[str]:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return [str(v) for v in value] if isinstance(value, list) else []
