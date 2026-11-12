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

"""Cloud Storage buckets: bucket settings and an object list, never contents.

Objects listed: the ones the agent names (or the prefixes it names); every
object (up to MAX_OBJECTS) when the use is bucket-wide (an MCP source that
allows the bucket, a data store that imports from it is scoped to its files).
Buckets that CES writes audio recordings to are not listed: their objects are
conversation data.
"""

from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING, Any

from cxas_scrapi.utils.passport.files import bucket_folder, safe_rel_subpath
from cxas_scrapi.utils.passport.http import NotReadable
from cxas_scrapi.utils.passport.iam import (
    IAM_POLICY_ROLES,
    READ_ROLES,
    policy_bindings,
)
from cxas_scrapi.utils.passport.plugins.base import Plugin, dump_json

if TYPE_CHECKING:
    from cxas_scrapi.utils.passport.graph import Node, WalkContext

API = "https://storage.googleapis.com/storage/v1/b"
MAX_OBJECTS = 1000
MAX_OBJECT_BYTES = 2 * 1024 * 1024
MAX_TOTAL_OBJECT_BYTES = 10 * 1024 * 1024
_FIELDS = "items(name,size,contentType,updated),nextPageToken"
RECORDING_PURPOSES = {"audio recordings", "evaluation audio"}


def _object_meta(item: dict[str, Any]) -> dict[str, Any]:
    size = item.get("size")
    return {
        "name": item.get("name"),
        "size": int(size) if str(size or "").isdigit() else size,
        "content_type": item.get("contentType"),
        "updated": item.get("updated"),
    }


class StorageBucketPlugin(Plugin):
    kind = "storage.bucket"
    service = "Cloud Storage"
    noun = "bucket"
    folder = "cloud_storage"

    def _bucket(self, node: Node) -> str:
        return node.ref.id.rsplit("/", 1)[-1]

    def fetch(self, node: Node, ctx: WalkContext) -> None:
        bucket = urllib.parse.quote(self._bucket(node), safe="")
        data = ctx.reader.get(f"{API}/{bucket}", area=self.kind)
        node.config = data
        node.location = data.get("location") or node.location
        owner = str(data.get("projectNumber") or "")
        node.project = ctx.project_key(owner) if owner else node.project
        node.extras["owned"] = (
            owner == ctx.project_number
            if owner and ctx.project_number
            else None
        )
        node.extras["objects"] = {}
        recordings_only = (
            bool(node.purposes) and set(node.purposes) <= RECORDING_PURPOSES
        )
        if recordings_only and not node.scope and not node.whole:
            node.extras["listing"] = (
                "not listed: CES writes conversation recordings here"
            )
        try:
            node.iam = policy_bindings(
                ctx.reader.get(f"{API}/{bucket}/iam", area=self.kind)
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

    def details(self, node: Node, ctx: WalkContext) -> None:
        objects: dict[str, Any] = node.extras["objects"]
        bucket = urllib.parse.quote(self._bucket(node), safe="")
        try:
            if node.whole and not node.whole_done:
                self._list(node, ctx, bucket, "", objects)
                node.extras["listing"] = "every object of the bucket"
            for item in sorted(node.scope - node.scope_done):
                if item in objects:
                    continue
                if item.endswith("/"):
                    self._list(node, ctx, bucket, item, objects)
                    continue
                try:
                    meta = ctx.reader.get(
                        f"{API}/{bucket}/o/{urllib.parse.quote(item, safe='')}",
                        area=self.kind,
                    )
                    objects[item] = _object_meta(meta)
                except NotReadable as exc:
                    if exc.category != "not_found":
                        raise
                    node.extras.setdefault("missing_objects", []).append(item)
            node.extras.setdefault("listing", "the objects the agent names")
        except NotReadable as exc:
            ctx.read_failed(
                exc,
                kind="storage.objects",
                rid=f"{node.ref.id}/objects",
                what="object list",
                role=READ_ROLES["storage.objects"],
                owner=node.ref,
            )
            return
        self._download_objects(node, ctx, bucket, objects)

    def _download_objects(
        self,
        node: Node,
        ctx: WalkContext,
        bucket: str,
        objects: dict[str, Any],
    ) -> None:
        recordings_only = (
            bool(node.purposes) and set(node.purposes) <= RECORDING_PURPOSES
        )
        if recordings_only or not hasattr(ctx.reader, "get_bytes"):
            return
        downloaded: dict[str, str] = node.extras.setdefault(
            "downloaded_files", {}
        )
        total_bytes = sum(len(v.encode("utf-8")) for v in downloaded.values())
        for name, meta in sorted(objects.items()):
            clean = safe_rel_subpath(name)
            if clean is None or clean in downloaded or name.endswith("/"):
                continue
            size = meta.get("size")
            if isinstance(size, int) and (
                size > MAX_OBJECT_BYTES
                or total_bytes + size > MAX_TOTAL_OBJECT_BYTES
            ):
                continue
            url = f"{API}/{bucket}/o/{urllib.parse.quote(name, safe='')}?alt=media"
            try:
                raw = ctx.reader.get_bytes(url, area=self.kind)
            except NotReadable:
                continue
            if (
                len(raw) > MAX_OBJECT_BYTES
                or total_bytes + len(raw) > MAX_TOTAL_OBJECT_BYTES
            ):
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            downloaded[clean] = text
            total_bytes += len(raw)

    def _list(
        self,
        node: Node,
        ctx: WalkContext,
        bucket: str,
        prefix: str,
        objects: dict[str, Any],
    ) -> None:
        token = ""
        while len(objects) < MAX_OBJECTS:
            query = f"maxResults=1000&fields={urllib.parse.quote(_FIELDS)}"
            if prefix:
                query += f"&prefix={urllib.parse.quote(prefix, safe='')}"
            if token:
                query += f"&pageToken={urllib.parse.quote(token, safe='')}"
            data = ctx.reader.get(f"{API}/{bucket}/o?{query}", area=self.kind)
            for item in data.get("items") or []:
                if len(objects) >= MAX_OBJECTS:
                    node.extras["truncated"] = True
                    break
                objects[str(item.get("name"))] = _object_meta(item)
            token = str(data.get("nextPageToken") or "")
            if not token:
                return
        node.extras["truncated"] = True

    def resource_folder(self, node: Node, ctx: WalkContext) -> str:
        return bucket_folder(
            self._bucket(node), ctx.project_id, ctx.project_number
        )

    def files(self, node: Node, ctx: WalkContext) -> dict[str, tuple[str, str]]:
        objects = node.extras.get("objects") or {}
        downloaded = node.extras.get("downloaded_files") or {}
        out: dict[str, tuple[str, str]] = {}
        for name, text in sorted(downloaded.items()):
            clean = safe_rel_subpath(name)
            if clean is not None:
                out[f"files/{clean}"] = (
                    text if text.endswith("\n") else text + "\n",
                    "downloaded bucket object",
                )
        undownloaded = set(objects) - set(downloaded)
        if undownloaded or node.extras.get("missing_objects") or not out:
            out["objects.json"] = (
                dump_json(
                    {
                        "listing": node.extras.get("listing"),
                        "truncated_at": MAX_OBJECTS
                        if node.extras.get("truncated")
                        else None,
                        "objects": [objects[k] for k in sorted(objects)],
                        "named_by_the_agent_but_missing": node.extras.get(
                            "missing_objects", []
                        ),
                    }
                ),
                "object list: name, size, type, last update",
            )
        return out

    def facts(self, node: Node) -> list[tuple[str, Any]]:
        cfg = node.config
        iam_cfg = cfg.get("iamConfiguration") or {}
        objects = node.extras.get("objects") or {}
        return [
            ("Used for", node.purposes or ["data the agent reads"]),
            ("Location", cfg.get("location")),
            ("Location type", cfg.get("locationType")),
            ("Storage class", cfg.get("storageClass")),
            (
                "Uniform bucket-level access",
                (iam_cfg.get("uniformBucketLevelAccess") or {}).get("enabled"),
            ),
            ("Public access prevention", iam_cfg.get("publicAccessPrevention")),
            ("Versioning", (cfg.get("versioning") or {}).get("enabled")),
            (
                "Lifecycle rules",
                len((cfg.get("lifecycle") or {}).get("rule") or []) or None,
            ),
            ("Retention policy", cfg.get("retentionPolicy")),
            ("Labels", cfg.get("labels")),
            ("Objects listed", len(objects) if objects else None),
            ("Object listing", node.extras.get("listing")),
            ("Owned by the source project", ctx_owned(node)),
        ]

    def summary(self, node: Node) -> dict[str, Any]:
        out = super().summary(node)
        out["bucket"] = self._bucket(node)
        out["objects"] = sorted(node.extras.get("objects") or {})
        return out


def ctx_owned(node: Node) -> bool | None:
    return node.extras.get("owned")
