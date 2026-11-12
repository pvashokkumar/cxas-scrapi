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

"""Cloud Functions (v2 API: gen1 and gen2): the live function config.

Edges: the service account it runs as, the secrets of its environment and
volumes, the Cloud Run service a gen2 function runs on (who may invoke it is
there), its VPC connector and the Artifact Registry repository of its image.
Plain environment values whose names look like credentials are redacted.
"""

from __future__ import annotations

import copy
import io
import urllib.parse
import zipfile
from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport import ids
from cxas_scrapi.utils.passport.files import safe_rel_subpath
from cxas_scrapi.utils.passport.graph import Edge
from cxas_scrapi.utils.passport.http import NotReadable
from cxas_scrapi.utils.passport.iam import IAM_POLICY_ROLES, policy_bindings
from cxas_scrapi.utils.passport.model import token_name
from cxas_scrapi.utils.passport.plugins.base import Plugin, dump_json
from cxas_scrapi.utils.passport.run_edges import identity_edge
from cxas_scrapi.utils.passport.run_spec import (
    ENV_CREDENTIAL_RE,
    NOT_SECRET_VALUE_RE,
)

if TYPE_CHECKING:
    from cxas_scrapi.utils.passport.graph import Node, WalkContext

API = "https://cloudfunctions.googleapis.com/v2"
GCS_API = "https://storage.googleapis.com/storage/v1/b"
MAX_SOURCE_ZIP_BYTES = 5 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 512 * 1024


def redact_function_env(config: dict[str, Any]) -> list[str]:
    """Redact credential-like plain environment values in place; returns the names."""
    redacted = []
    for section in ("serviceConfig", "buildConfig"):
        env = (config.get(section) or {}).get("environmentVariables")
        if not isinstance(env, dict):
            continue
        for name, value in list(env.items()):
            text = str(value)
            if (
                ENV_CREDENTIAL_RE.search(name)
                and not NOT_SECRET_VALUE_RE.match(text.strip())
                and not text.startswith("${")
            ):
                env[name] = "${" + token_name("REDACTED_ENV_", name) + "}"
                redacted.append(name)
    return redacted


def sanitize_function_config(config: dict[str, Any]) -> dict[str, Any]:
    """Strip server-generated deployment fields and internal Cloud Run hash URLs."""
    out = copy.deepcopy(config)
    for key in (
        "createTime",
        "updateTime",
        "satisfiesPzi",
        "satisfiesPzs",
        "uid",
        "etag",
    ):
        out.pop(key, None)
    build = out.get("buildConfig")
    if isinstance(build, dict):
        build.pop("build", None)
        build.pop("sourceProvenance", None)
        storage = (build.get("source") or {}).get("storageSource")
        if isinstance(storage, dict):
            storage.pop("generation", None)
    svc = out.get("serviceConfig")
    if isinstance(svc, dict):
        svc.pop("revision", None)
        svc.pop("uri", None)
    return out


class CloudFunctionPlugin(Plugin):
    kind = ids.FUNCTION
    service = "Cloud Functions"
    noun = "function"
    folder = "cloud_functions"

    def fetch(self, node: Node, ctx: WalkContext) -> None:
        config = copy.deepcopy(
            ctx.reader.get(f"{API}/{node.ref.id}", area=self.kind)
        )
        redacted = redact_function_env(config)
        if redacted:
            node.notes.append(
                "Credential-like environment values are not in the passport: "
                + ", ".join(f"`{n}`" for n in redacted)
                + "."
            )
        node.config = config
        parts = node.ref.id.split("/")
        project, region, name = parts[1], parts[3], parts[5]
        node.location = region
        node.extras.setdefault("source_files", {})
        if config.get("environment") == "GEN_2":
            try:
                run_svc = ctx.reader.get(
                    f"https://{region}-run.googleapis.com/apis/serving.knative.dev/v1/namespaces/{project}/services/{name}",
                    area=self.kind,
                )
                ann = (run_svc.get("metadata") or {}).get("annotations") or {}
                if ann.get("run.googleapis.com/invoker-iam-disabled") == "true":
                    config.setdefault("serviceConfig", {})[
                        "invokerIamDisabled"
                    ] = True
            except NotReadable:
                pass
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
                what="IAM policy",
                role=IAM_POLICY_ROLES[self.kind],
                owner=node.ref,
            )
        self.details(node, ctx)

    def details(self, node: Node, ctx: WalkContext) -> None:
        if node.extras.get("source_fetched"):
            return
        node.extras["source_fetched"] = True
        build = node.config.get("buildConfig") or {}
        src = (build.get("source") or {}).get("storageSource") or (
            build.get("sourceProvenance") or {}
        ).get("resolvedStorageSource")
        if not isinstance(src, dict):
            return
        bucket = str(src.get("bucket") or "")
        obj = str(src.get("object") or "")
        if not bucket or not obj or not hasattr(ctx.reader, "get_bytes"):
            return
        url = (
            f"{GCS_API}/{urllib.parse.quote(bucket, safe='')}/o/"
            f"{urllib.parse.quote(obj, safe='')}?alt=media"
        )
        try:
            raw = ctx.reader.get_bytes(url, area=self.kind)
        except NotReadable:
            return
        if not raw or len(raw) > MAX_SOURCE_ZIP_BYTES:
            return
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                extracted: dict[str, str] = {}
                for info in sorted(zf.infolist(), key=lambda i: i.filename):
                    clean = safe_rel_subpath(info.filename)
                    is_zip_symlink = (
                        info.external_attr >> 16
                    ) & 0o170000 == 0o120000
                    if (
                        info.is_dir()
                        or is_zip_symlink
                        or clean is None
                        or clean in ("function.json", "README.md")
                        or info.file_size > MAX_SOURCE_FILE_BYTES
                        or clean.startswith(("__MACOSX/", ".git/"))
                        or "/__pycache__/" in f"/{clean}"
                        or clean.endswith((".pyc", ".pyo", ".so"))
                    ):
                        continue
                    data = zf.read(info.filename)
                    try:
                        extracted[clean] = data.decode("utf-8")
                    except UnicodeDecodeError:
                        continue
                node.extras["source_files"] = extracted
        except zipfile.BadZipFile:
            return

    def edges(self, node: Node, ctx: WalkContext) -> list[Edge]:
        project, region = node.ref.id.split("/")[1], node.ref.id.split("/")[3]
        svc = node.config.get("serviceConfig") or {}
        build = node.config.get("buildConfig") or {}
        number = ctx.project_number if ctx.is_source(project) else None
        out: list[Edge] = []
        ident = identity_edge(ctx, svc.get("serviceAccountEmail"), number)
        if ident:
            out.append(ident)
        for item in svc.get("secretEnvironmentVariables") or []:
            out.append(
                Edge(
                    ids.SECRET,
                    ids.secret(
                        ctx,
                        str(item.get("projectId") or project),
                        str(item.get("secret")),
                    ),
                    f"environment variable `{item.get('key')}` comes from this secret",
                    project=ctx.project_key(
                        str(item.get("projectId") or project)
                    ),
                )
            )
        for item in svc.get("secretVolumes") or []:
            out.append(
                Edge(
                    ids.SECRET,
                    ids.secret(
                        ctx,
                        str(item.get("projectId") or project),
                        str(item.get("secret")),
                    ),
                    f"mounted as a file at {item.get('mountPath')}",
                    project=ctx.project_key(
                        str(item.get("projectId") or project)
                    ),
                )
            )
        if svc.get("vpcConnector"):
            connector = str(svc["vpcConnector"])
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
        repo = str(build.get("dockerRepository") or "")
        if repo and not repo.endswith("/repositories/gcf-artifacts"):
            parts = repo.split("/")
            if len(parts) >= 6 and parts[0] == "projects":
                out.append(
                    Edge(
                        ids.REPOSITORY,
                        f"projects/{ctx.project_key(parts[1])}/locations/{parts[3]}/repositories/{parts[5]}",
                        "container image of the function is stored in this repository",
                        project=ctx.project_key(parts[1]),
                        location=parts[3],
                    )
                )
        return out

    def files(self, node: Node, ctx: WalkContext) -> dict[str, tuple[str, str]]:
        out = {
            "function.json": (
                dump_json(sanitize_function_config(node.config)),
                "live function config",
            )
        }
        for name, text in sorted(
            (node.extras.get("source_files") or {}).items()
        ):
            out[name] = (
                text if text.endswith("\n") else text + "\n",
                "function source code",
            )
        return out

    def facts(self, node: Node) -> list[tuple[str, Any]]:
        cfg = node.config
        svc = cfg.get("serviceConfig") or {}
        build = cfg.get("buildConfig") or {}
        trigger = cfg.get("eventTrigger") or {}
        source = (build.get("source") or {}).get("storageSource") or {}
        return [
            ("URL", cfg.get("url") or svc.get("uri")),
            ("Generation", cfg.get("environment")),
            ("State", cfg.get("state")),
            ("Runtime", build.get("runtime")),
            ("Entry point", build.get("entryPoint")),
            ("Trigger", trigger.get("eventType") or "HTTP"),
            ("Service account", svc.get("serviceAccountEmail")),
            ("Ingress", svc.get("ingressSettings")),
            (
                "Invoker IAM check disabled",
                True if svc.get("invokerIamDisabled") else None,
            ),
            (
                "Environment variables",
                sorted(svc.get("environmentVariables") or {}),
            ),
            (
                "Secret environment variables",
                [
                    f"{s.get('key')} <- secret {s.get('secret')}"
                    for s in svc.get("secretEnvironmentVariables") or []
                ],
            ),
            ("Memory", svc.get("availableMemory")),
            ("CPU", svc.get("availableCpu")),
            ("Timeout seconds", svc.get("timeoutSeconds")),
            ("Min instances", svc.get("minInstanceCount")),
            ("Max instances", svc.get("maxInstanceCount")),
            ("Concurrency", svc.get("maxInstanceRequestConcurrency")),
            ("VPC connector", svc.get("vpcConnector")),
            (
                "Source",
                f"gs://{source.get('bucket')}/{source.get('object')}"
                if source
                else None,
            ),
            ("Build service account", build.get("serviceAccount")),
            ("Labels", cfg.get("labels")),
        ]
