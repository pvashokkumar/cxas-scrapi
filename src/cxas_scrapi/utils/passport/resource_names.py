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

"""Google Cloud resource names the passport recognizes in agent files.

`kind_of_resource_name("projects/p/locations/l/dataStores/d")` ->
("discoveryengine.dataStore", "projects/p/locations/l/collections/default_collection/dataStores/d").
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from cxas_scrapi.utils.passport import ids

if TYPE_CHECKING:
    from collections.abc import Callable

_SEG = r"[^/\"'\s`,;)}\]>]+"
_VERTEX_KINDS = {
    "endpoints": "aiplatform.endpoint",
    "ragCorpora": "aiplatform.ragCorpus",
    "indexEndpoints": "aiplatform.indexEndpoint",
    "featureOnlineStores": "aiplatform.featureOnlineStore",
    "cachedContents": "aiplatform.cachedContent",
}


def _discovery(m: re.Match[str]) -> tuple[str, str]:
    base, collection_kind, name = m.group(1), m.group(2), m.group(3)
    if "/collections/" not in base:
        base += "/collections/default_collection"
    kind = ids.DATA_STORE if collection_kind == "dataStores" else ids.ENGINE
    return kind, f"{base}/{collection_kind}/{name}"


_NAME_RES: tuple[
    tuple[re.Pattern[str], Callable[[re.Match[str]], tuple[str, str]]], ...
] = (
    (
        re.compile(
            rf"(projects/{_SEG}/locations/{_SEG}(?:/collections/{_SEG})?)/(dataStores|engines)/({_SEG})"
        ),
        _discovery,
    ),
    (
        re.compile(
            rf"projects/{_SEG}/locations/{_SEG}/(endpoints|ragCorpora|indexEndpoints|featureOnlineStores|cachedContents)/{_SEG}"
        ),
        lambda m: (_VERTEX_KINDS[m.group(1)], m.group(0)),
    ),
    (
        re.compile(rf"projects/{_SEG}/instances/{_SEG}/databases/{_SEG}"),
        lambda m: ("spanner.database", m.group(0)),
    ),
    (
        re.compile(
            rf"projects/{_SEG}/locations/{_SEG}/clusters/{_SEG}(?:/instances/{_SEG})?"
        ),
        lambda m: (
            "alloydb.instance"
            if "/instances/" in m.group(0)
            else "alloydb.cluster",
            m.group(0),
        ),
    ),
    (
        re.compile(rf"projects/{_SEG}/(topics|subscriptions)/{_SEG}"),
        lambda m: ("pubsub." + m.group(1)[:-1], m.group(0)),
    ),
    (
        re.compile(rf"projects/{_SEG}/locations/{_SEG}/queues/{_SEG}"),
        lambda m: ("cloudtasks.queue", m.group(0)),
    ),
    (
        re.compile(rf"projects/{_SEG}/locations/{_SEG}/workflows/{_SEG}"),
        lambda m: ("workflows.workflow", m.group(0)),
    ),
    (
        re.compile(rf"projects/{_SEG}/locations/{_SEG}/templates/{_SEG}"),
        lambda m: ("modelarmor.template", m.group(0)),
    ),
    (
        re.compile(
            rf"projects/{_SEG}/(?:locations/{_SEG}/)?(inspectTemplates|deidentifyTemplates)/{_SEG}"
        ),
        lambda m: ("dlp." + m.group(1)[:-1], m.group(0)),
    ),
    (
        re.compile(rf"projects/{_SEG}/locations/{_SEG}/connections/{_SEG}"),
        lambda m: ("connectors.connection", m.group(0)),
    ),
    (
        re.compile(
            rf"projects/{_SEG}/locations/{_SEG}/namespaces/{_SEG}/services/{_SEG}"
        ),
        lambda m: ("servicedirectory.service", m.group(0)),
    ),
)


def kind_of_resource_name(value: str) -> tuple[str, str] | None:
    """(kind, id) of a Google Cloud resource name the generic table knows."""
    for regex, build in _NAME_RES:
        m = regex.search(value)
        if m:
            return build(m)
    return None
