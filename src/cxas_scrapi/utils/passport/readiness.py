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

"""Target project readiness audit for `cxas push --passport`."""

from __future__ import annotations

import json
import time
import urllib.parse
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from cxas_scrapi.utils.passport.files import read_json
from cxas_scrapi.utils.passport.gcp import remote_fetch_allowed
from cxas_scrapi.utils.passport.http import NotReadable, make_reader
from cxas_scrapi.utils.passport.iam import dataset_bindings, policy_bindings
from cxas_scrapi.utils.passport.model import (
    PASSPORT_DIR_NAME,
    PASSPORT_MANIFEST_NAME,
)
from cxas_scrapi.utils.passport.plugins.discovery_engine import api_base
from cxas_scrapi.utils.passport.readiness_format import (
    MISCONFIGURED,
    MISSING,
    NOT_CHECKED,
    READY,
    format_readiness_report,
)

__all__ = [
    "MISCONFIGURED",
    "MISSING",
    "NOT_CHECKED",
    "READY",
    "ReadinessCheck",
    "audit_target_readiness",
    "format_readiness_report",
]

_GROUPS = ("bigquery", "cloud_run", "cloud_functions", "cloud_storage", "secret_manager", "vertex_ai_search", "iam")  # fmt: skip


@dataclass(frozen=True)
class ReadinessCheck:
    status: str
    kind: str
    resource: str
    detail: str
    remediation: str | None = None


def _folder_remedy(
    folder: str, files: list[str], preferred: tuple[str, ...], prefix: str
) -> str:
    picked = [f"{folder}/{f}" for f in preferred if f in files]
    return f"{prefix}: {' + '.join(picked)}" if picked else f"See: {folder}/"


class _Auditor:
    def __init__(
        self,
        reader: Any,
        values: dict[str, str],
        source_root: Path | None = None,
    ) -> None:
        self.reader, self.values, self.source_root = reader, values, source_root
        self.area = self.kind = self.label = ""

    def disk_files(self, folder: str, raw_files: Any) -> list[str]:
        files = list(raw_files or [])
        if self.source_root is not None:
            folder_path = self.source_root / folder
            if folder_path.is_dir():
                return [f for f in files if (folder_path / f).is_file()]
        return files

    def resolve(self, text: Any) -> str:
        out = str(text or "")
        for k, v in self.values.items():
            if v:
                out = out.replace(f"${{{k}}}", v)
        return out

    def project_of(self, entry: dict[str, Any]) -> str:
        return self.resolve(entry.get("project")) or self.values.get(
            "GCP_PROJECT", ""
        )

    def target(self, kind: str, label: str) -> None:
        self.area = f"readiness.{kind.split('.', 1)[0]}"
        self.kind, self.label = kind, label

    def ready(self, detail: str) -> ReadinessCheck:
        return ReadinessCheck(READY, self.kind, self.label, detail)

    def miss(self, detail: str, remedy: str | None = None) -> ReadinessCheck:
        return ReadinessCheck(MISSING, self.kind, self.label, detail, remedy)

    def miscfg(self, detail: str, remedy: str | None = None) -> ReadinessCheck:
        return ReadinessCheck(
            MISCONFIGURED, self.kind, self.label, detail, remedy
        )

    def probe(
        self, url: str, missing_detail: str, remedy: str | None = None
    ) -> tuple[dict[str, Any] | None, ReadinessCheck | None]:
        try:
            return self.reader.get(url, area=self.area), None
        except NotReadable as exc:
            if exc.category == "not_found":
                return None, self.miss(missing_detail, remedy)
            if exc.category == "api_disabled":
                proj = getattr(self.reader, "quota_project", "") or "target"
                svc = exc.service or "API"
                cmd = (
                    f"gcloud services enable {exc.service} --project={proj}"
                    if exc.service
                    else remedy
                )
                return None, self.miss(f"{svc} is disabled in `{proj}`", cmd)
            return None, ReadinessCheck(
                NOT_CHECKED, self.kind, self.label, str(exc)
            )

    def required_sa(self, entry: dict[str, Any]) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for b in (entry.get("iam") or {}).get("bindings") or []:
            if isinstance(b, dict):
                m = self.resolve(b.get("member"))
                r = str(b.get("role") or "").split(" (", 1)[0]
                if m.startswith("serviceAccount:") and "${" not in m and r:
                    out.append((m, r))
        return out

    def check_iam(
        self, entry: dict[str, Any], held: set[tuple[str, str]], cmd_tpl: str
    ) -> ReadinessCheck | None:
        for m, r in self.required_sa(entry):
            if (m, r) not in held:
                msg = f"missing IAM binding `{r}` for `{m}`"
                return self.miscfg(msg, cmd_tpl.format(m=m, r=r))
        return None

    def policy_iam(
        self,
        entry: dict[str, Any],
        url: str,
        cmd_tpl: str,
        *,
        is_get_iam: bool = True,
    ) -> ReadinessCheck | None:
        if not self.required_sa(entry):
            return None
        try:
            pol = (
                self.reader.get_iam_policy(url, area=self.area)
                if is_get_iam
                else self.reader.get(url, area=self.area)
            )
        except NotReadable:
            return None
        held = {(b.member, b.role) for b in policy_bindings(pol)}
        return self.check_iam(entry, held, cmd_tpl)

    def check_bigquery(self, entry: dict[str, Any]) -> ReadinessCheck:
        proj, ds = self.project_of(entry), self.resolve(entry.get("name"))
        folder = str(entry.get("folder") or f"passport/bigquery/{ds}")
        remedy = _folder_remedy(
            folder,
            self.disk_files(folder, entry.get("files")),
            ("schema.sql", "seed.sql"),
            "Run",
        )
        self.target("bigquery.dataset", f"BigQuery dataset `{ds}`")
        base = f"https://bigquery.googleapis.com/bigquery/v2/projects/{proj}/datasets/{ds}"
        ds_live, err = self.probe(
            base, f"dataset `{proj}.{ds}` does not exist", remedy
        )
        if err:
            return err
        tables = (entry.get("live") or {}).get("tables") or []
        missing_tables = [
            t
            for tbl in tables
            if isinstance(tbl, dict)
            and (t := str(tbl.get("name") or ""))
            and not t.startswith("${")
            and (
                terr := self.probe(
                    f"{base}/tables/{urllib.parse.quote(t)}", "", remedy
                )[1]
            )
            and terr.status == MISSING
        ]
        if missing_tables:
            return self.miss(
                f"missing table(s): {', '.join(missing_tables)}", remedy
            )
        held = {(b.member, b.role) for b in dataset_bindings(ds_live)}
        cmd = f"bq --project_id={proj} query --use_legacy_sql=false 'GRANT `{{r}}` ON SCHEMA `{proj}.{ds}` TO \"{{m}}\"'"
        iam_err = self.check_iam(entry, held, cmd)
        detail = (
            f"dataset and {len(tables)} table(s) present"
            if tables
            else "dataset present"
        )
        return iam_err or self.ready(detail)

    def check_cloud_run(self, entry: dict[str, Any]) -> ReadinessCheck:
        proj = self.project_of(entry)
        reg = str(entry.get("region") or entry.get("location") or "us-central1")
        svc = self.resolve(entry.get("service") or entry.get("name"))
        folder = str(entry.get("folder") or f"passport/cloud_run/{svc}")
        remedy = _folder_remedy(
            folder,
            self.disk_files(folder, entry.get("files")),
            ("service.yaml", "tools.yaml"),
            "Spec",
        )
        self.target("run.service", f"Cloud Run service `{svc}` ({reg})")
        url = f"https://{reg}-run.googleapis.com/apis/serving.knative.dev/v1/namespaces/{proj}/services/{svc}"
        live, err = self.probe(
            url, "service is not deployed in the target project", remedy
        )
        if err or live is None:
            return err or self.miss("service not found", remedy)
        if expected_raw := (entry.get("live") or {}).get("custom_audiences"):
            expected_resolved = self.resolve(expected_raw)
            try:
                expected_list = json.loads(expected_resolved)
            except ValueError:
                expected_list = [expected_resolved]
            ann = (live.get("metadata") or {}).get("annotations") or {}
            try:
                actual_list = json.loads(
                    str(ann.get("run.googleapis.com/custom-audiences") or "[]")
                )
            except ValueError:
                actual_list = []
            if missing_aud := [
                a for a in expected_list if a not in actual_list
            ]:
                amsg = f"missing custom audience(s) {missing_aud} (CES ID tokens will fail with 401)"
                acmd = f"gcloud run services update {svc} --region={reg} --project={proj} --set-custom-audiences={','.join(expected_list)}"
                return self.miscfg(amsg, acmd)
        iam_url = f"https://run.googleapis.com/v2/projects/{proj}/locations/{reg}/services/{svc}:getIamPolicy"
        cmd = f"gcloud run services add-iam-policy-binding {svc} --region={reg} --project={proj} --member='{{m}}' --role='{{r}}'"
        return self.policy_iam(entry, iam_url, cmd) or self.ready(
            "service deployed and configured"
        )

    def check_function(self, entry: dict[str, Any]) -> ReadinessCheck:
        proj = self.project_of(entry)
        loc = str(entry.get("location") or "us-central1")
        name = self.resolve(entry.get("name"))
        folder = str(entry.get("folder") or f"passport/cloud_functions/{name}")
        files = self.disk_files(folder, entry.get("files"))
        remedy = (
            f"Source: {folder}/ ({', '.join(files)})"
            if files
            else f"See: {folder}/"
        )
        self.target(
            "cloudfunctions.function", f"Cloud Function `{name}` ({loc})"
        )
        url = f"https://cloudfunctions.googleapis.com/v2/projects/{proj}/locations/{loc}/functions/{name}"
        _, err = self.probe(
            url, "function is not deployed in the target project", remedy
        )
        if err:
            return err
        if (entry.get("live") or {}).get("invoker_iam_check_disabled"):
            run_url = f"https://{loc}-run.googleapis.com/apis/serving.knative.dev/v1/namespaces/{proj}/services/{name}"
            try:
                run_svc = self.reader.get(run_url, area="readiness.run")
                ann = (run_svc.get("metadata") or {}).get("annotations") or {}
                if ann.get("run.googleapis.com/invoker-iam-disabled") != "true":
                    imsg = "Cloud Run invoker IAM check is not disabled (--no-invoker-iam-check)"
                    icmd = f"gcloud run services update {name} --region={loc} --project={proj} --no-invoker-iam-check"
                    return self.miscfg(imsg, icmd)
            except NotReadable:
                pass
        return self.ready("function deployed")

    def check_other(self, group: str, entry: dict[str, Any]) -> ReadinessCheck:
        proj = self.project_of(entry)
        name = self.resolve(entry.get("name"))
        qname = urllib.parse.quote(name, safe="@" if group == "iam" else "")
        if group == "cloud_storage":
            folder = str(entry.get("folder") or "passport/cloud_storage")
            self.target("storage.bucket", f"Cloud Storage bucket `{name}`")
            url = f"https://storage.googleapis.com/storage/v1/b/{qname}"
            _, err = self.probe(
                url, "bucket does not exist", f"Files: {folder}/files/"
            )
            cmd = f"gcloud storage buckets add-iam-policy-binding gs://{name} --member='{{m}}' --role='{{r}}'"
            return (
                err
                or self.policy_iam(entry, f"{url}/iam", cmd, is_get_iam=False)
                or self.ready("bucket present")
            )
        if group == "secret_manager":
            self.target(
                "secretmanager.secret", f"Secret Manager secret `{name}`"
            )
            url = f"https://secretmanager.googleapis.com/v1/projects/{proj}/secrets/{name}"
            _, err = self.probe(
                url,
                f"secret `{name}` does not exist in `{proj}`",
                f"Create secret `{name}` in `{proj}` and add a version",
            )
            cmd = f"gcloud secrets add-iam-policy-binding {name} --project={proj} --member='{{m}}' --role='{{r}}'"
            return (
                err
                or self.policy_iam(entry, f"{url}:getIamPolicy", cmd)
                or self.ready("secret present")
            )
        if group == "vertex_ai_search":
            rid = self.resolve(entry.get("id"))
            if entry.get("kind") == "discoveryengine.engine":
                folder = str(
                    entry.get("folder")
                    or f"passport/vertex_ai_search/engine-{name}"
                )
                self.target(
                    "discoveryengine.engine",
                    f"Vertex AI Search engine `{name}`",
                )
                _, err = self.probe(
                    f"{api_base(rid)}/{rid}",
                    "engine does not exist in the target project",
                    f"Config: {folder}/engine.json",
                )
                return err or self.ready("engine present")
            folder = str(
                entry.get("folder") or f"passport/vertex_ai_search/{name}"
            )
            self.target(
                "discoveryengine.dataStore",
                f"Vertex AI Search data store `{name}`",
            )
            _, err = self.probe(
                f"{api_base(rid)}/{rid}",
                "data store does not exist in the target project",
                f"Config: {folder}/data_store.json",
            )
            return err or self.ready("data store present")
        self.target("iam.serviceAccount", f"Service account `{name}`")
        url = f"https://iam.googleapis.com/v1/projects/{proj}/serviceAccounts/{qname}"
        remedy = f"gcloud iam service-accounts create {name.split('@', 1)[0]} --project={proj}"
        _, err = self.probe(
            url, "service account does not exist in the target project", remedy
        )
        return err or self.ready("service account present")


def audit_target_readiness(
    source_app_dir: str | Path,
    target_project_id: str | None,
    target_project_number: str | None = None,
    placeholder_values: dict[str, str] | None = None,
    apps_client: Any = None,
    reader: Any = None,
) -> dict[str, Any]:
    """Check whether `<target_project_id>` has the attached resources in `passport/manifest.json`."""
    root = Path(source_app_dir).resolve()
    manifest = read_json(root / PASSPORT_DIR_NAME / PASSPORT_MANIFEST_NAME)
    if not manifest or not target_project_id:
        return {"checked": False, "ready": True, "checks": []}
    if reader is None and remote_fetch_allowed(True):
        reader = make_reader(apps_client)
    if reader is None:
        return {"checked": False, "ready": True, "checks": []}
    if hasattr(reader, "quota_project"):
        reader.quota_project = target_project_id

    values: dict[str, str] = dict(placeholder_values or {})
    values["GCP_PROJECT"] = target_project_id
    if target_project_number:
        values["GCP_PROJECT_NUMBER"] = target_project_number

    started = time.perf_counter()
    before_timings = {
        k: float(v)
        for k, v in (getattr(reader, "timings_ms", None) or {}).items()
        if isinstance(v, int | float)
    }
    aud = _Auditor(reader, values, source_root=root)
    raw_resources = manifest.get("resources") or {}
    resources = raw_resources if isinstance(raw_resources, dict) else {}
    checks: list[ReadinessCheck] = []
    handlers: dict[str, Any] = {
        "bigquery": aud.check_bigquery,
        "cloud_run": aud.check_cloud_run,
        "cloud_functions": aud.check_function,
    }
    for group in _GROUPS:
        fn = handlers.get(group)
        for entry in resources.get(group) or []:
            if isinstance(entry, dict):
                checks.append(
                    fn(entry) if fn else aud.check_other(group, entry)
                )

    identities = manifest.get("identities") or []
    if identities:
        try:
            pol_url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{target_project_id}:getIamPolicy"
            policy = reader.get_iam_policy(
                pol_url, area="readiness.project_iam", post=True
            )
            held = {(b.member, b.role) for b in policy_bindings(policy)}
            for ident in identities:
                if not isinstance(ident, dict):
                    continue
                member = aud.resolve(ident.get("member"))
                if "${" in member:
                    continue
                for role in ident.get("project_roles") or []:
                    base_role = str(role).split(" (", 1)[0]
                    if (member, base_role) not in held:
                        lbl = f"IAM role `{base_role}` for `{member}`"
                        msg = f"missing on project `{target_project_id}`"
                        cmd = f"gcloud projects add-iam-policy-binding {target_project_id} --member='{member}' --role='{base_role}'"
                        checks.append(
                            ReadinessCheck(
                                MISSING, "project.iam", lbl, msg, cmd
                            )
                        )
        except NotReadable as exc:
            lbl = f"Project IAM policy `{target_project_id}`"
            checks.append(
                ReadinessCheck(NOT_CHECKED, "project.iam", lbl, str(exc))
            )

    ready = all(c.status in (READY, NOT_CHECKED) for c in checks)
    summary = {
        "ready": sum(1 for c in checks if c.status == READY),
        "missing": sum(1 for c in checks if c.status == MISSING),
        "misconfigured": sum(1 for c in checks if c.status == MISCONFIGURED),
        "not_checked": sum(1 for c in checks if c.status == NOT_CHECKED),
    }
    total_ms = round((time.perf_counter() - started) * 1000.0, 3)
    raw_timings = getattr(reader, "timings_ms", None)
    timings_by_kind: dict[str, float] = {}
    if isinstance(raw_timings, dict):
        for k in sorted(raw_timings):
            v = raw_timings[k]
            if not isinstance(v, int | float):
                continue
            if k.startswith("readiness."):
                delta = round(float(v) - before_timings.get(k, 0.0), 3)
                if delta >= 0.0 and (k not in before_timings or delta > 0.0):
                    timings_by_kind[k] = delta
    return {
        "checked": True,
        "target_project_id": target_project_id,
        "ready": ready,
        "summary": summary,
        "checks": [asdict(c) for c in checks],
        "latency_ms": {"total_readiness_audit_ms": total_ms},
        "timings_by_kind_ms": timings_by_kind,
    }
