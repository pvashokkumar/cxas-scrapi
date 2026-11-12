# CXAS Passport (`cxas pull --passport` / `cxas push --passport`)

**CXAS Passport** packages a Customer Engagement Suite (CES / CX Agent Studio) agent into a self-documenting, project-agnostic bundle with its live Google Cloud dependency blueprint, least-privilege IAM contract, pre-push invariant gates, and live target readiness verification.

---

## 1. Prerequisites

Install `cxas-scrapi` (see [Installation](../getting-started/installation.md)) and authenticate Application Default Credentials:

```bash
# Install as an isolated CLI tool with uv (or `pip install cxas-scrapi`)
uv tool install cxas-scrapi

# Authenticate Application Default Credentials
gcloud auth application-default login
```

---

## 2. Two-Command Workflow

### Step 1: Pull a Portable Bundle from a Source Project (Read-Only)

```bash
cxas pull "<AGENT_NAME_OR_ID>" \
  --project-id <SOURCE_PROJECT> --location us --passport
```

What `cxas pull --passport` does:
1. **Standard CES Paths Preserved:** Exports your agent's standard CES files (`app.json`, `environment.json`, `agents/`, `tools/`, `toolsets/`) into `./<AGENT_DIR>` and replaces hardcoded source project IDs and project numbers with `${GCP_PROJECT}` and `${GCP_PROJECT_NUMBER}`.
2. **Usage-Scoped Read-Only Discovery (`GET` / `:getIamPolicy` only):** Follows only active agent references (pruning unattached orphan toolsets) across BigQuery, Cloud Run (including mounted MCP Toolbox `tools.yaml`), Cloud Functions, Cloud Storage, Secret Manager, Vertex AI Search, API Gateway, Artifact Registry, Service Accounts, and 22 generic Google Cloud resource kinds.
3. **Generates Two Companion Artifacts:**
   - `PLACEHOLDERS.md`: Step-by-step setup checklist for a Cloud Admin, listing every discovered resource, the file/line evidence that pulled it in, required runtime IAM grants, and `gcloud` / `bq` provisioning commands.
   - `passport/`: Machine-readable `manifest.json` plus per-resource blueprints (`bigquery/<dataset>/schema.sql`, `cloud_run/<service>/service.yaml` + redacted `tools.yaml`, `cloud_functions/<fn>/`, `cloud_storage/<bucket>/`, `vertex_ai_search/<store>/`).
4. **Zero Secret Values & Zero Human PII:** Secret values are never exported (only secret names, metadata, and IAM accessors; mounted MCP `tools.yaml` configs have credentials redacted). Human `user:` and `group:` principals are stripped from IAM policies.

> **Note for customer agents:** Small tables (`<= 100` rows) also generate a `seed.sql` alongside `schema.sql` so demo transfers work out of the box. If you are testing on a customer agent and do not want to bring sample rows internally, delete `seed.sql` from `passport/bigquery/*/` before sharing.

---

### Step 2: Push & Audit Readiness in a Target Project

```bash
cxas push --app-dir ./<AGENT_DIR> \
  --project-id <TARGET_PROJECT> --location us --passport
```

What `cxas push --passport` does:
1. **Non-Destructive Stamping:** Copies the bundle to a temporary staging directory, resolves `${GCP_PROJECT}` and `${GCP_PROJECT_NUMBER}` (via Resource Manager lookup), and applies any `--set KEY=VALUE` overrides without mutating your local template files.
2. **6 Universal Pre-Push Gates (Before Upload):**
   - **Gate 1 (Fatal):** Valid `app.json` and `rootAgent` exists on disk.
   - **Gate 2 (Warn):** Connected agent graph (flags unreachable sub-agents).
   - **Gate 3 (Fatal):** Every `{@TOOL: ...}` and `{@AGENT: ...}` reference is bound in JSON and exists on disk.
   - **Gate 4 (Fatal):** All Python tools and callbacks exist and pass `ast.parse()`.
   - **Gate 5 (Warn):** Live/voice safety checks (hardcoded test OTPs, deeply nested output schemas).
   - **Gate 6 (Fatal):** Zero unresolved `${...}` placeholders remaining.
3. **Post-Upload CES Read-Back Verification:** Immediately exports the pushed app back from CES to confirm the model, toolsets, tools, and agent bindings were not silently dropped.
4. **Live `N/N` Target GCP Readiness Audit:** Verifies every discovered resource in the target project (`[READY]`, `[MISSING]`, `[MISCONFIGURED]`, or `[NOT_CHECKED]`), including Cloud Run `/mcp` custom audiences and IAM bindings, and prints exact `gcloud` / `bq` remediation commands for any gap.
5. **Provenance Ledger:** Appends a deployment record to `passport/ledger.jsonl`.

---

## 3. Passport Flags Reference

### `cxas pull` Passport Options

| Flag | Description |
| :--- | :--- |
| `--passport` | Export a portable Passport bundle (`PLACEHOLDERS.md` + `passport/manifest.json` + resource blueprints). |
| `--no-live-introspect` | Skip live Google Cloud resource reads; document only direct agent references offline. |
| `--strict` | CI mode: exit non-zero (`exit 1`) after writing the bundle if any attached resource could not be read. |

### `cxas push` Passport Options

| Flag | Description |
| :--- | :--- |
| `--passport` | Stamp Passport placeholders, run the 6 pre-push gates, verify CES read-back, and audit target readiness. |
| `--project-id <ID>` | Target GCP project ID (stamps `${GCP_PROJECT}` and looks up `${GCP_PROJECT_NUMBER}`). |
| `--project-number <NUM>` | Explicit target GCP project number for `${GCP_PROJECT_NUMBER}` (default: looked up from `--project-id`). |
| `--to <APP_NAME_OR_ID>` | Optional existing target app to update (combine with `--overwrite` to overwrite an existing app). |
| `--set KEY=VALUE` | Custom placeholder override (repeatable, e.g. `--set GCS_BUCKET_KB=my-bucket`). |
| `--toolbox-url <URL>` | Overrides MCP toolset endpoint URLs on push. |
| `--moh-uri <GS_URI>` | Overrides Music-on-Hold `gs://` URI across voice callbacks. |
| `--gcs-bucket <BUCKET>` | Overrides the audio/evaluation logging bucket in `app.json`. |
| `--skip-passport-gates` | Warn instead of aborting when a pre-push gate or post-upload CES read-back check fails. |
| `--strict` | CI mode: exit non-zero (`exit 1`) if any target readiness check is `[MISSING]` or `[MISCONFIGURED]`. |
| `--create-version` | Creates an immutable CES app version snapshot after a verified push. |

---

## 4. Permissions Reference (Viewer-Only on Source)

- **Source Project (`cxas pull --passport`):**
  - `roles/ces.viewer`, `roles/browser`, `roles/iam.securityReviewer`
  - Service viewers only for services your agent uses: `roles/bigquery.metadataViewer`, `roles/run.viewer`, `roles/cloudfunctions.viewer`, `roles/storage.bucketViewer` + `roles/storage.objectViewer`, `roles/secretmanager.viewer` (+ `roles/secretmanager.secretAccessor` *only* if Cloud Run mounts an MCP `tools.yaml` secret), `roles/discoveryengine.viewer`, `roles/iam.serviceAccountViewer`.
  - Missing a permission never crashes `pull`: the resource is marked `Not readable` in `PLACEHOLDERS.md` with the exact missing role (`--strict` fails in CI).
- **Target Project (`cxas push --passport`):**
  - `roles/ces.admin` (or editor) to import the CES app + `roles/browser` + viewer roles for the target readiness audit.

## Related Commands

- [`cxas pull`](pull.md) - Full reference for `cxas pull`.
- [`cxas push`](push.md) - Full reference for `cxas push`.
