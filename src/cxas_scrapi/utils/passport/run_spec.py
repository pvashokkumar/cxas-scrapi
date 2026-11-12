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

"""Cloud Run service specs (Knative `serving.knative.dev/v1`) read from the source."""

from __future__ import annotations

import copy
import re
from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport.mcp_config import (
    URL_PASSWORD_RE,
    is_mcp_toolbox_image,
)
from cxas_scrapi.utils.passport.model import token_name
from cxas_scrapi.utils.passport.render import DoubleQuoted
from cxas_scrapi.utils.passport.scan import SECRET_RE

if TYPE_CHECKING:
    from cxas_scrapi.utils.passport.model import RunService

DROP_SERVICE_ANNOTATIONS = {
    "serving.knative.dev/creator",
    "serving.knative.dev/lastModifier",
    "run.googleapis.com/client-name",
    "run.googleapis.com/client-version",
    "run.googleapis.com/operation-id",
    "run.googleapis.com/ingress-status",
    "run.googleapis.com/urls",
    "run.googleapis.com/creator",
    "run.googleapis.com/lastModifier",
    "run.googleapis.com/satisfiesPzs",
    "client.knative.dev/user-image",
}
DROP_ANNOTATION_PREFIXES = ("run.googleapis.com/build-",)
_DROP_TEMPLATE_LABELS = {"client.knative.dev/nonce"}
# Credential-like environment variable names (a word of the name, e.g. DB_PASSWORD, OPENAI_API_KEY).
ENV_CREDENTIAL_RE = re.compile(
    r"(?i)(?:^|[_-])(?:password|passwd|secret|token|api[_-]?key|apikey|private[_-]?key|credentials?|"
    r"access[_-]?key|secret[_-]?key|client[_-]?secret|dsn|connection[_-]?string|conn[_-]?str|bearer)(?:$|[_-])"
)
NOT_SECRET_VALUE_RE = re.compile(
    r"(?i)^(?:|\d+|true|false|yes|no|on|off|none|null)$"
)


def sanitize_knative_service(
    obj: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """The live service as `gcloud run services replace` takes it, plus notes."""
    notes: list[str] = []
    meta = obj.get("metadata") or {}
    out_meta: dict[str, Any] = {"name": meta.get("name")}
    if meta.get("namespace"):
        out_meta["namespace"] = meta["namespace"]
    if meta.get("labels"):
        out_meta["labels"] = dict(meta["labels"])
    annotations = {
        k: v
        for k, v in (meta.get("annotations") or {}).items()
        if k not in DROP_SERVICE_ANNOTATIONS
        and not k.startswith(DROP_ANNOTATION_PREFIXES)
    }
    if annotations:
        out_meta["annotations"] = annotations
    spec = copy.deepcopy(obj.get("spec") or {})
    template = spec.get("template") or {}
    tmeta = template.get("metadata") or {}
    for key in (
        "name",
        "creationTimestamp",
        "generation",
        "uid",
        "resourceVersion",
    ):
        tmeta.pop(key, None)
    if tmeta.get("labels"):
        tmeta["labels"] = {
            k: v
            for k, v in tmeta["labels"].items()
            if k not in _DROP_TEMPLATE_LABELS
        }
        if not tmeta["labels"]:
            tmeta.pop("labels")
    if tmeta.get("annotations"):
        tmeta["annotations"] = {
            k: v
            for k, v in tmeta["annotations"].items()
            if k not in DROP_SERVICE_ANNOTATIONS
            and not k.startswith(DROP_ANNOTATION_PREFIXES)
        }
        if not tmeta["annotations"]:
            tmeta.pop("annotations")
    tspec = template.get("spec") or {}
    mounted_vols = {
        vm.get("name")
        for c in tspec.get("containers") or []
        for vm in c.get("volumeMounts") or []
        if isinstance(vm, dict) and vm.get("name")
    }
    if tspec.get("volumes") and mounted_vols:
        tspec["volumes"] = [
            v
            for v in tspec["volumes"]
            if not isinstance(v, dict)
            or not v.get("secret")
            or v.get("name") in mounted_vols
        ]
    pinned = False
    for volume in tspec.get("volumes") or []:
        for item in (volume.get("secret") or {}).get("items") or []:
            if str(item.get("key", "")).isdigit():
                item["key"] = "latest"
                pinned = True
    for container in tspec.get("containers") or []:
        for env in container.get("env") or []:
            ref = ((env.get("valueFrom") or {}).get("secretKeyRef")) or {}
            if str(ref.get("key", "")).isdigit():
                ref["key"] = "latest"
                pinned = True
    if pinned:
        notes.append(
            "Secrets that the source pinned to a version number use `latest` here: version numbers do not carry over to another project."
        )
    traffic = spec.get("traffic") or []
    if any(
        t.get("revisionName")
        or t.get("tag")
        or int(t.get("percent", 100) or 0) != 100
        for t in traffic
    ):
        notes.append(
            "The source split traffic between revisions or used tags; service.yaml sends all traffic to the latest revision."
        )
    spec["traffic"] = [{"percent": 100, "latestRevision": True}]
    return {
        "apiVersion": obj.get("apiVersion") or "serving.knative.dev/v1",
        "kind": "Service",
        "metadata": out_meta,
        "spec": spec,
    }, notes


def redact_plain_env(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Replace credential-like plain environment values of a service spec, in place.

    A variable whose name looks like a credential (DB_PASSWORD, OPENAI_API_KEY,
    ...) gets `${REDACTED_ENV_<NAME>}`; a password inside a URL value gets
    `${REDACTED_ENV_<NAME>_PASSWORD}`. Values that cannot be secrets (empty,
    numbers, booleans) and `${...}` references stay. Returns the redactions.
    """
    redactions: list[dict[str, Any]] = []
    containers = (
        ((spec.get("spec") or {}).get("template") or {}).get("spec") or {}
    ).get("containers") or []
    for container in containers:
        for env in container.get("env") or []:
            if (
                not isinstance(env, dict)
                or "valueFrom" in env
                or not isinstance(env.get("value"), str)
            ):
                continue
            name = str(env.get("name") or "")
            value = env["value"]
            if (
                ENV_CREDENTIAL_RE.search(name)
                and not NOT_SECRET_VALUE_RE.match(value.strip())
                and not value.strip().startswith("${")
            ):
                placeholder = "${" + token_name("REDACTED_ENV_", name) + "}"
                env["value"] = DoubleQuoted(placeholder)
                redactions.append(
                    {
                        "key": name,
                        "placeholder": placeholder,
                        "container": container.get("name") or "",
                    }
                )
                continue
            m = URL_PASSWORD_RE.search(value)
            if m and not m.group("password").startswith("${"):
                placeholder = (
                    "${" + token_name("REDACTED_ENV_", f"{name}_PASSWORD") + "}"
                )
                env["value"] = DoubleQuoted(
                    value[: m.start("password")]
                    + placeholder
                    + value[m.end("password") :]
                )
                redactions.append(
                    {
                        "key": f"{name} (password in URL)",
                        "placeholder": placeholder,
                        "container": container.get("name") or "",
                    }
                )
    return redactions


def secret_aliases(tmeta: dict[str, Any]) -> dict[str, tuple[str | None, str]]:
    """`run.googleapis.com/secrets` annotation: alias -> (project, secret)."""
    raw = str(
        (tmeta.get("annotations") or {}).get("run.googleapis.com/secrets") or ""
    )
    aliases: dict[str, tuple[str | None, str]] = {}
    for part in raw.split(","):
        if ":" not in part:
            continue
        alias, path = part.split(":", 1)
        m = SECRET_RE.search(path)
        if m:
            aliases[alias.strip()] = (m.group("project"), m.group("secret"))
    return aliases


def apply_service_spec(svc: RunService, spec: dict[str, Any]) -> None:
    """Fill the identity, image, env and mounted secrets of `svc` from its spec."""
    template = (spec.get("spec") or {}).get("template") or {}
    tmeta = template.get("metadata") or {}
    tspec = template.get("spec") or {}
    aliases = secret_aliases(tmeta)

    def _secret_name(name: str) -> tuple[str | None, str]:
        return aliases.get(name, (None, name))

    svc.service_account = tspec.get("serviceAccountName") or None
    containers = tspec.get("containers") or []
    svc.image = containers[0].get("image") if containers else None
    svc.is_mcp_toolbox = any(
        is_mcp_toolbox_image(c.get("image")) for c in containers
    )
    volumes = {v.get("name"): v for v in tspec.get("volumes") or []}
    mounted: dict[str, list[str]] = {}
    for container in containers:
        cname = container.get("name") or ""
        for env in container.get("env") or []:
            ref = ((env.get("valueFrom") or {}).get("secretKeyRef")) or {}
            if ref.get("name"):
                project, name = _secret_name(str(ref["name"]))
                svc.env.append(
                    {
                        "container": cname,
                        "name": env.get("name"),
                        "secret": name,
                        "secret_project": project,
                    }
                )
            else:
                svc.env.append(
                    {
                        "container": cname,
                        "name": env.get("name"),
                        "value": env.get("value", ""),
                    }
                )
        for vm in container.get("volumeMounts") or []:
            mounted.setdefault(vm.get("name"), []).append(
                str(vm.get("mountPath") or "")
            )
    for vname, volume in volumes.items():
        secret = volume.get("secret")
        if isinstance(secret, dict) and secret.get("secretName"):
            project, name = _secret_name(str(secret["secretName"]))
            svc.secret_volumes.append(
                {
                    "volume": vname,
                    "secret": name,
                    "secret_project": project,
                    "items": secret.get("items") or [],
                    "mounted": vname in mounted,
                    "mount_paths": mounted.get(vname, []),
                }
            )


def find_mcp_config_file(
    svc: RunService, spec: dict[str, Any]
) -> tuple[str | None, str, str, str] | None:
    """(secret project, secret, version, file path) of the config file the MCP server reads."""
    template = (spec.get("spec") or {}).get("template") or {}
    tspec = template.get("spec") or {}
    aliases = secret_aliases(template.get("metadata") or {})
    volumes = {v.get("name"): v for v in tspec.get("volumes") or []}
    for container in tspec.get("containers") or []:
        args = [
            str(a)
            for a in (container.get("command") or [])
            + (container.get("args") or [])
        ]
        arg_paths = {a.split("=", 1)[1] for a in args if "=" in a} | {
            a for a in args if a.startswith("/")
        }
        for vm in container.get("volumeMounts") or []:
            secret = (volumes.get(vm.get("name")) or {}).get("secret")
            if not isinstance(secret, dict) or not secret.get("secretName"):
                continue
            items = secret.get("items") or [
                {"key": "latest", "path": secret["secretName"]}
            ]
            for item in items:
                full = (
                    str(vm.get("mountPath") or "").rstrip("/")
                    + "/"
                    + str(item.get("path") or "")
                )
                if full in arg_paths or (
                    svc.is_mcp_toolbox
                    and full.endswith((".yaml", ".yml"))
                    and not arg_paths
                ):
                    project, name = aliases.get(
                        str(secret["secretName"]),
                        (None, str(secret["secretName"])),
                    )
                    return project, name, str(item.get("key") or "latest"), full
    return None
