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

"""Run a passport v4 pull of the test world against the fake cloud."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from passport_v4_cloud import FakeCloud, default_routes
from passport_v4_world import APP_NAME, PROJECT, write_app

from cxas_scrapi.utils.passport.export import run_passport_export
from cxas_scrapi.utils.passport.http import ApiReader

if TYPE_CHECKING:
    from pathlib import Path


@dataclass
class Pull:
    """The pulled app folder, the fake cloud it read, the backoff sleeps, the report."""

    app: Path
    cloud: FakeCloud
    sleeps: list[float]
    report: dict[str, Any]

    def manifest(self) -> dict[str, Any]:
        return json.loads((self.app / "passport" / "manifest.json").read_text())

    def text(self, rel: str) -> str:
        return (self.app / rel).read_text(encoding="utf-8")

    def files(self) -> dict[str, str]:
        return {
            str(p.relative_to(self.app)): p.read_text(encoding="utf-8")
            for p in sorted(self.app.rglob("*"))
            if p.is_file()
        }

    def statuses(self, kind: str) -> set[str]:
        return {
            r["status"] for r in self.report["resources"] if r["kind"] == kind
        }


def pull_world(
    tmp_path: Path,
    routes: dict | None = None,
    *,
    live: bool = True,
    strict: bool = False,
    files: dict[str, str] | None = None,
) -> Pull:
    """Write the test app under `tmp_path` (with `files` replaced) and run the v4 export on it."""
    app = write_app(tmp_path)
    for rel, text in (files or {}).items():
        (app / rel).write_text(text, encoding="utf-8")
    cloud = FakeCloud(routes)
    sleeps: list[float] = []
    report = run_passport_export(
        app_root=app,
        project_id=PROJECT,
        location="us",
        app_name=APP_NAME,
        live_introspect=live,
        reader=ApiReader(cloud, sleep=sleeps.append),
        strict=strict,
    )
    return Pull(app, cloud, sleeps, report)


def routes_with(**overrides: Any) -> dict:
    """The default routes with some GET URLs answered differently."""
    routes = default_routes()
    for url, response in overrides.items():
        routes[("GET", url)] = response
    return routes
