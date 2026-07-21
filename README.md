# azure-assess

Python tooling to collect Azure configuration data, evaluate it for known findings, and review the results locally in a web dashboard.

## Overview

This repository currently has three main Python entry points:

- `azure-collect.py`: connects to Azure through the Azure CLI and writes collected JSON datasets to disk.
- `azure-findings.py`: reads the collected JSON and evaluates it against a library of predefined checks, then writes findings output.
- `azure-present.py`: starts a local Flask dashboard for browsing collected datasets and findings.

The normal workflow is:

1. Run `azure-collect.py` to gather raw data.
2. Run `azure-findings.py` to generate findings from that data.
3. Run `azure-present.py` to inspect the datasets and findings in a browser.

## Installation

Example installation steps:

```bash
apt install pipenv
curl -fsSL 'https://azurecliprod.blob.core.windows.net/$root/deb_install.sh' | sudo bash
git clone https://github.com/yg-ht/azure-assess.git
cd azure-assess
pipenv install -r requirements.txt
```

You may also want to pre-emptively install / re-install the Az CLI extensions. This can be done with:

```bash
AZURE_EXTENSION_DIR="$PWD/.azure-cliextensions" pipenv run bash -lc '
set -euo pipefail

EXT_DIR="${AZURE_EXTENSION_DIR:?AZURE_EXTENSION_DIR must be set}"
EXTS=(
  application-insights
  bastion
  databricks
  datafactory
  ml
)

echo "[*] Using Azure CLI:"
az version --output jsonc

echo "[*] Using extension dir: $EXT_DIR"
mkdir -p "$EXT_DIR"

for ext in "${EXTS[@]}"; do
  echo "[*] Removing extension: $ext"
  az extension remove --name "$ext" --only-show-errors >/dev/null 2>&1 || true
  rm -rf "$EXT_DIR/$ext"
done

az config set extension.use_dynamic_install=no --only-show-errors >/dev/null

for ext in "${EXTS[@]}"; do
  echo "[*] Installing extension: $ext"
  az extension add --name "$ext" --yes --only-show-errors
done

echo "[*] Installed extensions:"
az extension list --query "[].{name:name,version:version,path:path}" --output table

echo "[*] Verifying Azure ML command group:"
az ml --help >/dev/null

echo "[OK] Azure CLI extensions reinstalled cleanly and az ml loads"
'```

## Script Reference

### `azure-collect.py`

Purpose:
Collect JSON configuration data from the target Azure tenant or subscription and save it into an output directory. This is the raw data capture stage for the rest of the tooling.

Typical usage:

```bash
mkdir -p ~/azure-collect-data
pipenv run python azure-collect.py -o ~/azure-collect-data
```

Parameters:

- `-o`, `--output-dir`: directory where collected JSON files are written. Default: `azure-collect`
- `-d`, `--debug`: enable debug output
- `-e`, `--endpoint`: collect only endpoints matching the supplied text instead of collecting everything
- `-l`, `--listendpoints`: list all non-parameterised endpoints and exit
- `-L`, `--listparamendpoints`: list all parameterised endpoints and exit
- `-n`, `--donotenrich`: disable enrichment steps and perform enumeration only
- `-p`, `--paramendpointsonly`: collect only parameter-driven datasets
- `--max-workers`: maximum concurrent Azure CLI collection workers. Default: `4`; use `1` for serial execution
- `--timing-summary`, `--no-timing-summary`: enable or disable the final Azure CLI timing summary. Enabled by default
- `--collect-managed-role-definitions-cache`: collect only Microsoft-managed built-in Azure RBAC role definitions into the cache, remove subscription-specific role definition IDs, and exit
- `--managed-role-definitions-cache-path`: path for the managed role definition cache. Default: `reference/azure_builtin_role_definitions.json`
- `--auth-method`: authentication mode for Azure CLI. Supported values: `existing`, `device-code`, `browser`, `service-principal`, `managed-identity`. Default: `existing`
- `--tenant-id`: Azure tenant ID for login and/or context selection. Defaults to `AZURE_TENANT_ID`
- `--subscription-id`: Azure subscription ID to select after authentication. Defaults to `AZURE_SUBSCRIPTION_ID`
- `--client-id`: service principal or user-assigned managed identity client ID. Defaults to `AZURE_CLIENT_ID`
- `--client-secret`: service principal client secret. Defaults to `AZURE_CLIENT_SECRET`
- `--client-certificate`: certificate path for service principal auth. Defaults to `AZURE_CLIENT_CERTIFICATE_PATH`
- `--client-certificate-password`: certificate password for service principal auth. Defaults to `AZURE_CLIENT_CERTIFICATE_PASSWORD`

Notes:

- The script expects the Azure CLI to be installed and available on `PATH`.
- Some collection endpoints require Azure CLI extensions, such as `application-insights` and `azure-iot`. The script enables Azure CLI dynamic extension install and will also try `az extension add --name <extension>` when Azure CLI reports a missing extension.
- The default authentication mode is `existing`, which reuses the current Azure CLI session and does not trigger a login flow.
- If `--auth-method existing` is used and no valid Azure CLI session is present, the tool exits with guidance instead of forcing device code authentication.
- Authentication validation checks both the current Azure account context and token acquisition for Azure Resource Manager and Microsoft Graph before collection starts.
- `--subscription-id` applies the Azure CLI account context after authentication and can also be supplied through `AZURE_SUBSCRIPTION_ID`.
- Output files are timestamped in their filenames, which is used by the dashboard to track dataset history.
- Every collection run also writes `azure-collection-manifest_<timestamp>.json`. The manifest records the selected endpoint executions, whether each execution succeeded, returned no records, failed, was unauthorised, was skipped, or was not attempted, plus record counts and SHA-256 hashes for generated datasets.
- A manifest run status of `partial` means an endpoint failed, was unauthorised or was not attempted, or the top-level workflow did not complete. Legitimately skipped endpoints remain visible individually. Review `endpoint_runs`, `errors`, and `limitations` before treating an absent finding as evidence of a secure configuration.
- Manifest command entries use configured command templates rather than substituted commands. Credential- and token-like values are redacted, and raw Azure CLI output is not persisted in the manifest.
- Normal collection combines live custom Azure RBAC role definitions with the managed role definition cache when it exists. If the cache has not been generated, the collector falls back to a live full role definition collection.
- Managed role definition cache generation skips customer-facing collection and permission baseline checks so the cache is not mixed with customer custom roles or audit output.

Authentication examples:

```bash
# Reuse an existing Azure CLI session
az login
pipenv run python azure-collect.py --auth-method existing

# Trigger device code login explicitly
pipenv run python azure-collect.py --auth-method device-code --tenant-id <tenant-id>

# Trigger browser-based login explicitly
pipenv run python azure-collect.py --auth-method browser --tenant-id <tenant-id>

# Use service principal credentials from environment variables
export AZURE_TENANT_ID=<tenant-id>
export AZURE_CLIENT_ID=<client-id>
export AZURE_CLIENT_SECRET=<client-secret>
export AZURE_SUBSCRIPTION_ID=<subscription-id>
pipenv run python azure-collect.py --auth-method service-principal

# Use a user-assigned managed identity
export AZURE_CLIENT_ID=<managed-identity-client-id>
pipenv run python azure-collect.py --auth-method managed-identity --subscription-id <subscription-id>
```

### `azure-findings.py`

Purpose:
Analyse the JSON produced by `azure-collect.py`, print a status summary for all checks, and generate SARIF output for the findings in the `found` state.

Typical usage:

```bash
pipenv run python azure-findings.py -i ~/azure-collect-data
```

Parameters:

- `-i`, `--input-dir`: directory containing JSON produced by `azure-collect.py`. Relative paths are resolved next to `azure-findings.py`. Default: `azure-collect` next to `azure-findings.py`
- `-o`, `--output-file`: path for the SARIF 2.1.0 findings output. Relative paths are resolved below `<input-dir>`. Default: `<input-dir>/azure-findings.json`
- `--no-save`: do not write findings JSON files; print summary output only
- `--flat-output-file`: path for the flattened findings output used by `azure-present.py`. Relative paths are resolved below `<input-dir>`. Default: `<input-dir>/azure-findings-flat.json`
- `--report-ready-output-file`: path for the versioned report-ready findings export. Relative paths are resolved below `<input-dir>`. Default: `<input-dir>/azure-findings-report-ready.json`
- `--review-file`: optional versioned JSON file containing analyst review overrides keyed by canonical `finding_id`. Relative paths are resolved below `<input-dir>`
- `--baseline-findings-file`: optional prior `azure-findings-flat.json` used for conservative retest comparison. Relative paths are resolved below `<input-dir>`

Outputs:

- `azure-findings.json`: SARIF 2.1.0 output containing the full set of findings in the `found` state
- `azure-findings-flat.json`: flattened findings rows for easier dashboard display
- `azure-findings-report-ready.json`: versioned, compact report-processing export containing selected findings, publication readiness, report groups, and auditable exclusions

Finding definition metadata:

- Every evaluated check has a unique, lower-case `finding_id`. SARIF uses this canonical ID as `ruleId`, and the flat output includes it alongside each row.
- Existing requested-headline identifiers remain available in `definition.check_ids`. These are compatibility aliases and may be shared by related checks, so consumers should use `finding_id` as the primary key.
- `definition` also records its schema and definition versions, report title, category, default severity, and a versioned `report` narrative contract. Narrative fields remain explicitly marked `not_authored` until report text is curated rather than being populated with unsafe generic advice.

Normalised reporting data:

- Each finding includes a versioned `reporting` object containing deduplicated `assets`, content-addressed `observations`, and `provenance`. Existing `evidence` and `references` fields remain unchanged for compatibility.
- Assets distinguish Azure resources, subscriptions, Microsoft Entra principals, named resources, and assessment scopes. Observations retain the original evidence values and link them to stable asset IDs without copying generated navigation references into the observation data.
- Current source attribution is explicitly marked `finding_level`, because the checks currently identify the set of input datasets used by a finding rather than the exact source record for every evidence item.
- When a collection manifest is available, provenance links the collection run and source endpoint, verifies each source dataset against its recorded SHA-256 hash, and exposes partial runs, hash mismatches, and unavailable metadata as limitations. Collections created before manifests were introduced remain supported.

Azure and engagement context:

- Each finding includes a versioned `context` object which separates engagement metadata, finding-family classification, affected scope, selected family-specific attributes, and limitations.
- Engagement context records collected tenant and subscription identities, subscription display names and state where available, the selected subscription, collection run identity and timing, and whether the manifest and subscription inventory were available. Missing scope data is declared rather than inferred.
- Family metadata classifies every current finding under a stable report family and Azure service, identifies the relevant control plane, and supplies a primary report subject such as a storage account, Entra tenant identity, Kubernetes cluster, or SQL server.
- Scope context summarises affected asset names and kinds, subscription IDs, resource groups, resource types, Azure locations, and observation counts. Resource ID components are parsed case-insensitively from normalised Azure resource identifiers when separate fields are absent.
- `context.attributes` contains only an allow-listed set of report-useful fields for its family, such as network protocols and ports, identity and role types, runtime or TLS versions, public-network settings, or monitoring destinations. Arbitrary evidence keys, credentials, tokens, and keys are not copied into context. Extraction depth, traversal, string length, and repeated values are bounded, with truncation recorded as a limitation.
- Context remains a concise index into `reporting.assets` and `reporting.observations`; it does not replace the underlying evidence or claim that unavailable location or resource metadata was assessed.

Assessment coverage:

- Each finding includes a versioned `coverage` object with a denominator, affected observation and asset counts, an optional affected percentage, and explicit limitations.
- Current denominators are labelled `proxy`: they count unique identifiable assets in the first populated primary source, or source records when stable asset identities are unavailable. Duplicate asset records are counted once.
- Percentages are emitted only when affected asset identities match an asset denominator. A found result with unmatched identities does not emit a misleading zero-percent value.
- Cross-dataset correlation checks provide their explicit eligible assets and use the `check_specific_eligible_assets` denominator basis. Existing single-dataset checks continue to use conservative collected-population proxies until they are migrated.
- Missing data and unimplemented checks use `unavailable` and `not_implemented` coverage states instead of numeric claims.

Offline cross-dataset correlations:

- Exact logical dataset aliases and collection-manifest endpoint states distinguish complete, empty, partial, failed, missing, and pre-manifest inputs. Positive evidence can still be surfaced from a partial collection, but incomplete inputs cannot support a `not_found` conclusion.
- Critical-resource lock analysis applies `ReadOnly` and `CanNotDelete` locks inherited from subscription and resource-group scopes. Eligibility is limited to the versioned critical-resource profile, and a missing lock is reported only when lock collection is complete.
- Azure Policy analysis selects the latest resource/assignment/definition state, excludes compliant, exempt, and not-applicable records, separates explicit evaluation errors from non-compliance, and compares enforced assignments with the versioned Microsoft cloud security benchmark expectation. Missing assignments require a complete assignment inventory, while evaluation-error conclusions require both Policy states and events. The benchmark initiative identifier is documented by [Microsoft's Azure Policy built-in index](https://learn.microsoft.com/azure/governance/policy/samples/).
- Active Azure Advisor security recommendations are correlated with Defender assessments using exact resource and control identifiers first. Strong title similarity is retained as an explicitly inferred match and never suppresses unmatched evidence.
- Public-network settings are correlated with approved, successfully provisioned private endpoint connections for Storage, Key Vault, Container Registry, App Service, App Configuration, Application Gateway, Cosmos DB, Machine Learning, and Azure AI Search. A private endpoint is not treated as removing exposure while public access remains enabled.
- Application registrations, service principals, managed identities, groups, role assignments, and role definitions are correlated to identify privileged non-human principals at tenant, management-group, and subscription scopes. Credential expiry uses the collection completion time and emits metadata only; group membership is declared unavailable because it is not collected.
- Internet ingress analysis follows assigned public IPs through direct NICs, load-balancer rules and Application Gateway listeners to resolved backends. NSG decisions apply first-match priority across source address sets, the translated backend destination and port, Azure default inbound deny, and the intersection of effective NIC/subnet layers. Unknown NSG decisions do not establish reachability; effective route data is supporting evidence rather than proof of service exploitability.

Analyst review:

- Found checks default to an `unreviewed` `candidate` disposition and remain included for report-ready processing. Candidates are not silently excluded merely because an analyst has not reviewed them yet.
- Automated evidence confidence is derived separately from observations, collection status, endpoint completeness, and dataset integrity. It is labelled `automated`; an analyst override may replace it with explicitly sourced analyst confidence.
- Analyst dispositions include `confirmed`, `false_positive`, `accepted_risk`, `duplicate`, `informational`, `not_applicable`, and the default status-derived dispositions. The emitted review metadata marks false positives, duplicates, inconclusive checks, and non-findings for exclusion from subsequent report-ready processing.
- Every override requires a reviewer and a timezone-aware `reviewed_at` value. Unknown finding IDs, duplicate entries, invalid dispositions, malformed timestamps, and unsupported schemas fail validation.
- An override may include `contextual_severity` with a severity level and mandatory rationale. Automated confidence, affected population, and exposure context are recorded as decision factors, but never change severity automatically.

Example review file:

```json
{
  "schema_version": "1.0",
  "reviews": [
    {
      "finding_id": "storage_blob_public_access_level_is_disabled",
      "disposition": "confirmed",
      "confidence": {
        "level": "high",
        "rationale": "The affected storage account was verified in the Azure portal."
      },
      "contextual_severity": {
        "level": "Critical",
        "rationale": "The affected production account exposes regulated customer data."
      },
      "reviewer": "Analyst name",
      "reviewed_at": "2026-07-21T12:00:00Z",
      "notes": "Confirmed during manual review."
    }
  ]
}
```

Grouping, deduplication, and retesting:

- Each finding includes a versioned `triage` object. Stable report groups use family, service, tenant, and subscription dimensions; observation groups collect evidence affecting the same normalised assets.
- Exact duplicate observations are identified using their data, asset IDs, and source files. A canonical observation and duplicate IDs are recorded, but all original evidence remains in `reporting.observations` and existing outputs.
- A stable finding fingerprint uses the canonical finding ID and concrete asset identities, falling back to assessment scope where evidence has no concrete asset. Fingerprints do not include mutable evidence values or current finding status.
- Supplying `--baseline-findings-file` compares current rows with the same canonical definitions from a prior flat output. Outcomes distinguish new, persistent, potentially resolved, unchanged non-detections, changed scope, same-run comparisons, and inconclusive results. Definitions absent from the baseline remain explicitly not assessed.
- `potentially_resolved` requires matching engagement scope, a different run, a current `not_found` result, measurable current assessment coverage, a successful collection run, hash-verified source datasets, and successful or empty relevant endpoint results. It is deliberately not labelled resolved because analyst verification may still be required.
- Retest metadata records persisting, new, and potentially resolved asset IDs without deleting or changing current evidence. Stale baseline IDs, duplicate rows, invalid statuses, malformed envelopes, and baseline files over 100 MiB fail validation.

Report-ready export:

- Selection is driven by `review.report_ready.include`. Every unreviewed `candidate` remains selected by default, alongside confirmed, accepted-risk, and informational dispositions. False positives, duplicates, non-findings, and other excluded dispositions remain in the compact `excluded_findings` audit list.
- Selection is separate from publication readiness. Each selected finding lists blockers such as missing analyst review, unauthored report narrative, insufficient evidence confidence, unavailable coverage, or absence of a positive automated result. Candidates therefore remain visible for processing without being misrepresented as ready to publish.
- The assessment envelope consolidates engagement context, selection policy, summary counts, and stable report groups. Finding records contain definition and narrative fields, evaluation status, workflow state, contextual severity, affected assets, coverage, provenance, grouping, fingerprint, retest data, and attributed limitations.
- Exact duplicate observations are represented once using their canonical observation while duplicate IDs and original, emitted, and duplicate counts remain explicit. The original flat and SARIF outputs retain every observation.
- The export does not copy legacy raw `evidence`. Normalised observation data is recursively checked for credential-bearing field names, connection strings, private keys, JWTs, and signed URLs. Redacted values use `[REDACTED]`, and exact redaction paths are recorded. Traversal depth, node counts, and individual string lengths are bounded.
- Analyst-authored narrative, rationale, and notes are also passed through the report redaction boundary. Analysts should still avoid placing credentials in review files or report prose.

### `azure-present.py`

Purpose:
Run a local web interface for browsing the collected datasets and findings output. The dashboard now groups timestamped dataset versions and defaults to the latest collected snapshot for each dataset type.

Typical usage:

```bash
pipenv run python azure-present.py -i ~/azure-collect-data
```

Parameters:

- `-i`, `--input-dir`: directory containing collected JSON and optional findings output. Default: `azure-collect`

Notes:

- The Flask app listens on `127.0.0.1:5000`.
- The dashboard shows the latest dataset snapshot by default and allows switching to older timestamped versions where available.
- If `azure-findings-flat.json` exists in the input directory, findings are also available through the dashboard.

## Example End-to-End Usage

```bash
mkdir -p ~/azure-collect-data
pipenv run python azure-collect.py -o ~/azure-collect-data
pipenv run python azure-findings.py -i ~/azure-collect-data
pipenv run python azure-present.py -i ~/azure-collect-data
```

Then open `http://127.0.0.1:5000/` in a browser.
