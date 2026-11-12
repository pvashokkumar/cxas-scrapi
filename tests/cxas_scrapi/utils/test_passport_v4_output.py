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

"""Passport layout v4 output: people are never named, and two pulls of an
unchanged agent write the same files (APIs return maps in a varying order).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from passport_v4_cloud import DS, FN, SM, default_routes
from passport_v4_pull import pull_world
from passport_v4_resources import function, quota_gated
from passport_v4_world import FN_SA, NUMBER, PERSON, TEAM

if TYPE_CHECKING:
    from pathlib import Path


def test_people_who_may_read_a_secret_are_counted_not_named(
    tmp_path: Path,
) -> None:
    routes = default_routes()
    routes[("GET", f"{SM}/loyalty-api-key:getIamPolicy")] = (
        200,
        {
            "bindings": [
                {
                    "role": "roles/secretmanager.secretAccessor",
                    "members": [
                        f"user:{PERSON}",
                        f"group:{TEAM}",
                        f"serviceAccount:{FN_SA}",
                    ],
                }
            ]
        },
    )
    pull = pull_world(tmp_path, routes)
    for rel, text in pull.files().items():
        assert PERSON not in text, rel
        assert TEAM not in text, rel
    (sec,) = [
        s
        for s in pull.manifest()["resources"]["secret_manager"]
        if s["name"] == "loyalty-api-key"
    ]
    assert sec["iam"]["people_and_groups_not_listed"] == 2
    assert (
        sec["iam"]["bindings"][0]["member"]
        == "serviceAccount:loyalty-fn-sa@${GCP_PROJECT}.iam.gserviceaccount.com"
    )


def test_data_store_schema_is_written_the_same_way_every_pull(
    tmp_path: Path,
) -> None:
    """The API returns the JSON schema with its keys in a varying order."""
    fields = [("title", {"type": "string"}), ("body", {"type": "string"})]

    def schema_file(name: str, order: list) -> str:
        routes = default_routes()
        routes[("GET", f"{DS}/schemas/default_schema")] = quota_gated(
            {
                "name": "default_schema",
                "jsonSchema": json.dumps(
                    {"type": "object", "properties": dict(order)}
                ),
            }
        )
        pull = pull_world(tmp_path / name, routes)
        return pull.text(
            "passport/vertex_ai_search/policy-docs/data_store.json"
        )

    first = schema_file("a", fields)
    assert first == schema_file("b", list(reversed(fields)))
    assert json.loads(first)["schema"]["jsonSchema"]["properties"]["title"] == {
        "type": "string"
    }


def test_maps_in_any_order_write_the_same_bundle(tmp_path: Path) -> None:
    """APIs return `labels` in a different order on each read."""
    labels = [("app", "orders"), ("purpose", "demo"), ("team", "cx")]

    def pull_with(name: str, order: list) -> dict[str, str]:
        routes = default_routes()
        body = {
            "name": f"projects/{NUMBER}/secrets/loyalty-api-key",
            "replication": {"automatic": {}},
            "labels": dict(order),
        }
        routes[("GET", f"{SM}/loyalty-api-key")] = (200, body)
        fn_body = function()
        fn_body["labels"] = dict(order)
        routes[("GET", FN)] = (200, fn_body)
        files = pull_world(tmp_path / name, routes).files()
        manifest = json.loads(files.pop("passport/manifest.json"))
        manifest.pop("introspection")  # timings differ from run to run
        files["manifest"] = json.dumps(manifest, indent=2)
        return files

    first = pull_with("a", labels)
    second = pull_with("b", list(reversed(labels)))
    assert first == second
    assert (
        '"app": "orders",\n    "purpose": "demo"'
        in (first["passport/cloud_functions/loyalty-api/function.json"])
    )
