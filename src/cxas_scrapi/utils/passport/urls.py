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

"""Which resource a URL in the agent points at.

`*.run.app` -> Cloud Run service (the generated `<svc>-<hash>-<code>.a.run.app`
form is matched against the source project's services); `<region>-<project>
.cloudfunctions.net/<fn>` -> Cloud Function; `*.gateway.dev` -> API Gateway
gateway (matched against the source project's gateways); `*.appspot.com` ->
App Engine app; anything else -> an external endpoint (recorded, never read).
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport import ids
from cxas_scrapi.utils.passport.http import NotReadable
from cxas_scrapi.utils.passport.iam import READ_ROLES
from cxas_scrapi.utils.passport.model import token_name
from cxas_scrapi.utils.passport.scan import (
    RUN_DETERMINISTIC_HOST_RE,
    RUN_HASH_HOST_RE,
)

if TYPE_CHECKING:
    from cxas_scrapi.utils.passport.graph import WalkContext

_FUNCTION_HOST_RE = re.compile(
    r"^(?P<region>[a-z]+-[a-z]+\d+)-(?P<project>[a-z][a-z0-9-]+)\.cloudfunctions\.net$"
)
_APPSPOT_HOST_RE = re.compile(
    r"^(?:[a-z0-9-]+-dot-)?(?P<project>[a-z][a-z0-9-]+)\.(?:[a-z0-9]+\.r\.)?appspot\.com$"
)
_GATEWAY_HOST_RE = re.compile(r"^[a-z0-9-]+\.[a-z0-9-]+\.gateway\.dev$")


@dataclass
class Target:
    kind: str
    id: str
    name: str
    project: str | None = None
    location: str | None = None
    hints: dict[str, Any] = field(default_factory=dict)


def _list_everywhere(
    ctx: WalkContext, collection: str, api: str, kind: str, what: str
) -> list[dict[str, Any]]:
    """Items of `<api>/projects/<source>/locations/-/<collection>`, listed once.

    A failed listing is recorded as a read failure: the URLs it would match
    stay external endpoints.
    """
    key = f"list:{kind}"
    if key in ctx.cache:
        return ctx.cache[key]
    items: list[dict[str, Any]] = []
    if ctx.live and ctx.reader is not None and ctx.project_id:
        base = f"{api}/projects/{ctx.project_id}/locations/-/{collection}"
        token = ""
        try:
            for _ in range(20):
                url = f"{base}?pageSize=100"
                if token:
                    url += f"&pageToken={urllib.parse.quote(token, safe='')}"
                data = ctx.reader.get(url, area=kind)
                items += [
                    s for s in data.get(collection) or [] if isinstance(s, dict)
                ]
                token = str(data.get("nextPageToken") or "")
                if not token:
                    break
        except NotReadable as exc:
            ctx.read_failed(
                exc,
                kind=kind,
                rid=f"projects/{ctx.project_id}/locations/-/{collection}",
                what=what,
                role=READ_ROLES[kind],
                impact=f"those URLs of the agent are recorded as external endpoints and the {collection} behind them are not described",
            )
    ctx.cache[key] = items
    return items


def _hash_target(host: str, url: str, ctx: WalkContext) -> Target | None:
    services = _list_everywhere(
        ctx,
        "services",
        "https://run.googleapis.com/v2",
        ids.RUN,
        "Cloud Run service list (matches `*.a.run.app` URLs to services)",
    )
    for item in services:
        hosts = {
            urllib.parse.urlsplit(str(u)).hostname
            for u in [item.get("uri"), *(item.get("urls") or [])]
            if u
        }
        if host not in hosts:
            continue
        parts = str(item.get("name") or "").split("/")
        if len(parts) < 6:
            return None
        deterministic = [
            str(u).rstrip("/")
            for u in item.get("urls") or []
            if RUN_DETERMINISTIC_HOST_RE.match(
                urllib.parse.urlsplit(str(u)).hostname or ""
            )
        ]
        rewrite = (
            deterministic[0]
            if deterministic
            else "${" + token_name("CLOUD_RUN_URL_", parts[5]) + "}"
        )
        return Target(
            ids.RUN,
            ids.run_service(ctx, parts[1], parts[3], parts[5]),
            parts[5],
            project=ctx.project_key(parts[1]),
            location=parts[3],
            hints={"urls": [url], "url_rewrites": [(host, rewrite)]},
        )
    return None


def _gateway_target(host: str, url: str, ctx: WalkContext) -> Target | None:
    gateways = _list_everywhere(
        ctx,
        "gateways",
        "https://apigateway.googleapis.com/v1",
        ids.GATEWAY,
        "API Gateway gateway list (matches `*.gateway.dev` URLs to gateways)",
    )
    for item in gateways:
        parts = str(item.get("name") or "").split("/")
        if (
            str(item.get("defaultHostname") or "").lower() == host
            and len(parts) == 6
        ):
            return Target(
                ids.GATEWAY,
                "/".join(
                    ["projects", str(ctx.project_key(parts[1])), *parts[2:]]
                ),
                parts[5],
                project=ctx.project_key(parts[1]),
                location=parts[3],
                hints={"urls": [url]},
            )
    return None


def classify_url(url: str, ctx: WalkContext) -> Target:
    """The node a URL the agent calls belongs to."""
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    det = RUN_DETERMINISTIC_HOST_RE.match(host)
    if det:
        project = ctx.project_key(det.group("number"))
        return Target(
            ids.RUN,
            ids.run_service(
                ctx, project, det.group("region"), det.group("service")
            ),
            det.group("service"),
            project=project,
            location=det.group("region"),
            hints={"urls": [url]},
        )
    found = (
        _hash_target(host, url, ctx)
        if RUN_HASH_HOST_RE.match(host)
        else _gateway_target(host, url, ctx)
        if _GATEWAY_HOST_RE.match(host)
        else None
    )
    if found:
        return found
    fn = _FUNCTION_HOST_RE.match(host)
    path = [p for p in parts.path.split("/") if p]
    if fn and path:
        return Target(
            ids.FUNCTION,
            ids.function(ctx, fn.group("project"), fn.group("region"), path[0]),
            path[0],
            project=ctx.project_key(fn.group("project")),
            location=fn.group("region"),
            hints={"urls": [url]},
        )
    app = _APPSPOT_HOST_RE.match(host)
    if app:
        project = app.group("project")
        return Target(
            "appengine.app",
            f"apps/{project}",
            project,
            project=project,
            hints={"urls": [url]},
        )
    hints: dict[str, Any] = {"urls": [url]}
    if host.endswith((".run.app", ".gateway.dev")):
        hints["note"] = "no resource of the source project has this URL"
    return Target(ids.ENDPOINT, f"https://{host}", host or url, hints=hints)
