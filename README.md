# azure-assess

Python tooling to collect Azure configuration data, evaluate it for known findings, and review the results locally in a web dashboard.

## Overview

This repository has three main Python entry points:

- `azure-collect.py`: connects to Azure through the Azure CLI and writes collected JSON datasets to disk.
- `azure-findings.py`: reads the collected JSON and evaluates it against a library of predefined checks, then writes findings output.
- `azure-present.py`: starts a local Flask dashboard for browsing collected datasets and findings.

Supporting files are organised by purpose:

- `azure_assess/`: internal Python modules used by the three entry points.
- `scripts/`: customer and environment setup helpers.
- `tests/`: the automated test suite.
- `reference/`: version-controlled reference data used during collection.

The setup helpers are:

- `scripts/Azure-Graph-Collect-App.ps1`: creates a certificate-authenticated Microsoft Graph application for authorised Azure and Microsoft 365 assessment collection.
- `scripts/install-azure-cli-extensions.sh`: cleanly reinstalls the Azure CLI extensions used by the collector.

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

You may also want to pre-emptively reinstall the Azure CLI extensions used by the collector:

```bash
./scripts/install-azure-cli-extensions.sh
```

## Script Reference

### `scripts/install-azure-cli-extensions.sh`

Purpose:
Remove and reinstall the Azure CLI extensions used by `azure-collect.py`, then verify that the Azure Machine Learning command group loads. The script uses `.azure-cliextensions` below the current directory by default. Set `AZURE_EXTENSION_DIR` before running it to use a different dedicated extension directory.

### `scripts/Azure-Graph-Collect-App.ps1`

Purpose:
Create a temporary, single-tenant Microsoft Entra application and service principal that can authenticate using an X.509 certificate. By default, the script configures and grants the complete Microsoft Graph `All` permission profile, Azure subscription roles, and list-only metadata access for non-RBAC Key Vaults required by `azure-collect.py`.

This is a customer helper intended to be run by tenant and subscription administrators on Windows. Graph consent and Azure role assignment are separate operations and can require different administrator accounts. A normal run requires `-AzureSubscriptionIds`; use the explicit skip switches only for deliberately restricted provisioning.

Prerequisites:

- Windows PowerShell 5.1 or PowerShell 7 on Windows.
- The `Microsoft.Graph.Authentication` and `Microsoft.Graph.Applications` modules. Install the Microsoft Graph module for the current user with `Install-Module Microsoft.Graph -Scope CurrentUser`.
- A tenant administrator account. Privileged Role Administrator is the recommended role.
- Delegated `Application.ReadWrite.All` and `AppRoleAssignment.ReadWrite.All` scopes for the administrator running the script.
- Unless `-SkipAzureRoleAssignments` is used, the `Az.Accounts`, `Az.Resources`, and `Az.KeyVault` modules and Azure rights to create role definitions and role assignments at each requested subscription.
- Unless `-SkipAzureRoleAssignments` or `-SkipLegacyKeyVaultAccessPolicies` is used, `Microsoft.KeyVault/vaults/accessPolicies/write` rights for applicable non-RBAC vaults.
- An X.509 public certificate in a format such as `.cer`, `.crt`, or `.pem`. Keep the matching private key on the authorised collector host; do not give the script a `.pfx` or `.p12` file.

Creating the collector certificate on Linux:

Run the following commands on the authorised Linux collector host with OpenSSL installed. They create an encrypted private key, a 90-day self-signed certificate, the public `.cer` file supplied to the Windows administrator, and the combined PEM credential required by Azure CLI:

```bash
umask 077
mkdir -m 700 azure-assess-certificate
cd azure-assess-certificate

openssl req -x509 -newkey rsa:3072 -sha256 -days 90 -keyout collector-private-key.pem -out collector-public.crt -subj "/CN=YGHT Azure Assessment Graph Collector"

openssl x509 -in collector-public.crt -outform DER -out collector-public.cer

cat collector-private-key.pem collector-public.crt > collector-auth.pem
chmod 600 collector-private-key.pem collector-auth.pem

openssl x509 -in collector-public.crt -noout -subject -fingerprint -sha256 -dates

# Optional password and private-key integrity check; press Ctrl+C at the passphrase prompt to skip.
openssl pkey -in collector-private-key.pem -check -noout
```

OpenSSL prompts for a passphrase for `collector-private-key.pem`. Use a strong value and do not put it on the command line. The final, optional command prompts for the passphrase again and confirms that it unlocks a structurally valid private key; press Ctrl+C at that prompt to skip the check. `collector-public.crt` and `collector-public.cer` contain only the public certificate. `collector-private-key.pem` and `collector-auth.pem` contain the encrypted private key and must not leave the Linux collector host.

Transfer only `collector-public.cer` to the customer administrator. The administrator runs the app-registration helper on Windows:

```powershell
.\scripts\Azure-Graph-Collect-App.ps1 `
  -TenantId "11111111-2222-3333-4444-555555555555" `
  -CertificatePath ".\collector-public.cer" `
  -AzureSubscriptionIds "66665555-7777-4444-8888-555999666000"
```

After the Windows administrator returns the generated connection details, choose exactly one collector authentication mode. The modes are mutually exclusive for a collection run; there is one Azure CLI account context, and Azure Resource Manager and Microsoft Graph calls both use tokens obtained from that context.

`--auth-method existing` is the normal, non-invasive mode. It reuses whichever user, managed identity, client-secret, or certificate identity is already signed in to Azure CLI. The collector does not log in again and ignores the tool-managed service-principal credential variables. That existing identity must itself have the required Azure rights and Microsoft Graph permissions; permissions assigned by the setup helper to a different application do not transfer to the signed-in identity.

To use the normal existing-session mode, authenticate before starting the collector:

```bash
az login
# Or, for a certificate-authenticated existing session:
az login --service-principal \
  --username "<application-client-id>" \
  --certificate "/secure/path/collector-auth-unencrypted.pem" \
  --tenant "<tenant-id>"

pipenv run python azure-collect.py --auth-method existing
```

Current Azure CLI accepts an unencrypted combined PEM for this manual certificate-login command and has no certificate-password option. Protect that file with mode `0600` and remove any short-lived decrypted copy after login. To keep the stored combined PEM encrypted, use the tool-managed certificate workflow below instead.

`--auth-method service-principal` is the tool-managed alternative. It starts a new Azure CLI service-principal session and therefore must not be combined with `--auth-method existing`. The Azure CLI certificate command requires a combined PEM containing the private key followed by the public certificate. For tool-managed login with the encrypted combined PEM created above, configure the tenant ID, application client ID, subscription ID, combined PEM path and certificate passphrase:

```bash
export AZURE_TENANT_ID="<tenant-id>"
export AZURE_CLIENT_ID="<application-client-id>"
export AZURE_SUBSCRIPTION_ID="<subscription-id>"
export AZURE_CLIENT_CERTIFICATE_PATH="$PWD/azure-assess-certificate/collector-auth.pem"

read -rsp "Certificate passphrase: " AZURE_CLIENT_CERTIFICATE_PASSWORD
echo
export AZURE_CLIENT_CERTIFICATE_PASSWORD

pipenv run python azure-collect.py --auth-method service-principal

unset AZURE_CLIENT_CERTIFICATE_PASSWORD
```

The collector unlocks an encrypted PEM through OpenSSL, writes the decrypted key and certificate to a mode-`0600` temporary PEM, supplies that path to Azure CLI's `--certificate` option, and removes the temporary file immediately after `az login` completes. The passphrase is passed to OpenSSL through standard input and is not forwarded to Azure CLI. An unencrypted combined PEM can be used by omitting `AZURE_CLIENT_CERTIFICATE_PASSWORD`; Azure CLI then receives the original PEM path directly.

Client-secret service-principal login remains available as a distinct alternative:

```bash
export AZURE_TENANT_ID="<tenant-id>"
export AZURE_CLIENT_ID="<application-client-id>"
export AZURE_SUBSCRIPTION_ID="<subscription-id>"

read -rsp "Client secret: " AZURE_CLIENT_SECRET
echo
export AZURE_CLIENT_SECRET

pipenv run python azure-collect.py --auth-method service-principal

unset AZURE_CLIENT_SECRET
```

Do not configure both `AZURE_CLIENT_SECRET` and `AZURE_CLIENT_CERTIFICATE_PATH` for service-principal mode. The collector rejects this ambiguous combination instead of silently selecting one credential. Credential variables do not trigger a login when `--auth-method existing` is selected. The administrator sessions used by `Azure-Graph-Collect-App.ps1` to create permissions and role assignments are provisioning sessions only; they are separate from either collector authentication mode.

A customer certificate-authority-issued certificate may be used instead when required by organisational policy.

Permission profiles:

- `IdentityBaseline`: directory, application, policy, audit, reporting, authentication-method, entitlement-management, identity-risk, and on-premises directory-synchronisation data.
- `PIM`: privileged access data, eligible Entra role schedules, and role-management alerts.
- `M365Audit`: Microsoft 365 audit-query, service-activity, organisation-wide service settings, Forms settings, and SharePoint tenant settings.
- `EndpointIntune`: BitLocker, Intune configuration, managed-device, Intune RBAC, and service-configuration data.
- `GlobalSecureAccess`: Microsoft Entra Global Secure Access information and configuration.
- `DefenderHunting`: Defender identity health and sensors, security incidents, and advanced hunting.
- `All`: all of the profiles above.

The default is `All`, so customers running a full penetration test do not need to select profiles. Profiles remain available for deliberately restricted assessments; for example, `-Profiles IdentityBaseline,PIM`.

The `All` profile is additive. It retains the original 41 Graph application permissions for compatibility with other authorised assessment tools and adds the current least-privilege directory/group PIM schedule permissions required by Azure Assess. Moving Azure-resource PIM collection to ARM does not remove `PrivilegedAccess.Read.AzureResources` from the helper.

Parameters:

- `-DisplayName`: application display name. Defaults to a dated YGHT Azure Assessment collector name.
- `-TenantId`: tenant to connect to. When omitted, Microsoft Graph prompts for tenant selection during sign-in.
- `-CertificatePath`: required path to the public certificate. Private-key containers with `.pfx` or `.p12` extensions are rejected.
- `-Profiles`: one or more predefined permission profiles. Default: `All`.
- `-AzureSubscriptionIds`: subscription IDs on which to grant `Reader`, `Security Reader`, `Key Vault Reader`, and the fixed Azure Assess specialised-collection role. Required unless `-SkipAzureRoleAssignments` is used. Supplying it causes a separate Azure Resource Manager administrator login when required.
- `-SkipAzureRoleAssignments`: explicitly create a Graph-only application without assigning Azure roles or legacy Key Vault access policies. The resulting application cannot perform the corresponding Azure collection unless equivalent rights already exist.
- `-SkipLegacyKeyVaultAccessPolicies`: retain the default Azure RBAC grants but do not add list-only key and secret permissions to non-RBAC Key Vaults. Use only when legacy-vault metadata collection is deliberately excluded or equivalent access already exists.
- `-NoGrant`: configure the requested API permissions without creating app-role assignments. The script prints an administrator-consent URL instead.
- `-AllowDuplicateDisplayName`: allow creation when an application with the same display name already exists.
- `-WhatIf`: show the proposed application-registration creation without changing the tenant.

Important behaviour:

- Without `-NoGrant`, application-permission grants take effect immediately. Review the selected profiles before approving the operation.
- A normal run grants every collection-required permission. The Graph `All` profile is selected and granted by default; Azure subscription role assignments and legacy Key Vault list-only policies are also default. `-Profiles`, `-NoGrant`, `-SkipAzureRoleAssignments`, and `-SkipLegacyKeyVaultAccessPolicies` are explicit restrictions. No required permission depends on an opt-in parameter.
- `Reader` supports general ARM inventory and Azure-resource PIM reads. `Security Reader` supports Microsoft Defender for Cloud inventory. `Key Vault Reader` exposes key and secret metadata but not values.
- The fixed Azure Assess specialised-collection role contains the collector's remaining required operations: NIC effective NSG and route calculation, VM run-command metadata reads, Cost Management and Application Insights queries, Key Vault secret metadata reads, App Service configuration-list operations, storage account key listing, and storage blob reads. Storage keys and blob contents are sensitive evidence; grant this role only for an authorised assessment and remove it after collection. The role does not contain write, delete, recovery, cryptographic or secret-value Key Vault data actions.
- The Azure roles are assigned to the new service principal. They apply to `--auth-method service-principal`; they do not add rights to a user or managed identity used with `--auth-method existing`.
- RBAC-enabled Key Vaults use `Key Vault Reader`. By default, access-policy vaults receive equivalent list-only key and secret metadata permissions. This never grants secret `Get`, key recovery, cryptographic, write or delete permissions. Use `-SkipLegacyKeyVaultAccessPolicies` to opt out, and review the `-WhatIf` output because the default changes every applicable legacy vault in the selected subscriptions.
- The script validates every requested permission against the enabled Microsoft Graph application roles exposed by the tenant before creating the application. Availability can vary by cloud and workload; review the current [Microsoft Graph permissions reference](https://learn.microsoft.com/graph/permissions-reference).
- Only the certificate's public bytes are uploaded. The private key is neither read from a public certificate nor written to the output.
- The generated `<display-name>.connection-details.json` file contains tenant, application, service-principal, certificate, profile, and permission identifiers, plus an optional `Connect-MgGraph` command for a Windows Graph client. It does not contain a client secret or private key.
- The generated connection details are operational engagement data and should still be stored and transferred appropriately.
- Linux collection uses the combined `collector-auth.pem` credential directly through Azure CLI.
- If the script fails after reporting an application or service-principal object ID, inspect and remove any partially created tenant objects before retrying.
- Remove the application registration, enterprise application, Graph permission grants, Azure role assignments, the YGHT Azure Assessment Collector custom role when no longer used, local certificate, and generated connection details when the assessment is complete, subject to the engagement's evidence-retention requirements.

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
- `--client-certificate`: combined PEM path for tool-managed service-principal certificate authentication. The PEM must contain the private key followed by the public certificate. Defaults to `AZURE_CLIENT_CERTIFICATE_PATH`
- `--client-certificate-password`: optional password used locally to unlock an encrypted combined PEM through OpenSSL. Prefer `AZURE_CLIENT_CERTIFICATE_PASSWORD` so the value is not exposed in command-line arguments

Notes:

- The script expects the Azure CLI to be installed and available on `PATH`.
- Azure CLI commands are executed as argument vectors without a command shell. Resource names, resource groups and IDs containing spaces, parentheses or shell metacharacters therefore remain literal Azure CLI arguments.
- Some collection endpoints require Azure CLI extensions, such as `application-insights` and `azure-iot`. The script enables Azure CLI dynamic extension install and will also try `az extension add --name <extension>` when Azure CLI reports a missing extension.
- The default authentication mode is `existing`, which reuses the current Azure CLI session and does not trigger a login flow.
- If `--auth-method existing` is used and no valid Azure CLI session is present, the tool exits with guidance instead of forcing device code authentication.
- Existing mode does not read or validate client-secret or certificate files. Tool-managed service-principal mode requires exactly one of a client secret or combined PEM certificate and uses Azure CLI's distinct `--password` and `--certificate` options respectively.
- Encrypted combined PEM use requires OpenSSL. Temporary decrypted PEM files are created with owner-only permissions and removed after the login attempt. Azure CLI does not accept `.pfx` or `.p12` files for this login path.
- Authentication validation checks both the current Azure account context and token acquisition for Azure Resource Manager and Microsoft Graph before collection starts.
- `--subscription-id` applies the Azure CLI account context after authentication and can also be supplied through `AZURE_SUBSCRIPTION_ID`.
- Output files are timestamped in their filenames, which is used by the dashboard to track dataset history.
- Every collection run also writes a version 2.5 `azure-collection-manifest_<timestamp>.json`. The manifest records the selected endpoint executions, whether each execution succeeded, returned no records, failed, was unauthorised, was restricted by tenant licensing or capability, was skipped, or was not attempted, plus record counts and SHA-256 hashes for generated datasets. Failed request records include the Azure CLI return code, directly returned error message, and an Azure error code when the response supplies one. Error messages remain limited to 1,000 characters and explicitly indicate truncation.
- Before customer-facing collection begins, the collector non-interactively inspects applicable Azure role assignments, their role definitions and Azure deny assignments at the selected subscription, together with the non-secret permission claims in the Microsoft Graph access token. The access-verification record is deliberately bounded and never includes the token or authentication credentials. These checks are observational: they neither suppress collection requests nor change the existing permission-baseline continuation prompt.
- Each endpoint execution records a conservative access-verification result. `access_verified` means the tool demonstrated an unconditional subscription-wide ARM read grant without an applicable read deny, or an applicable Graph application permission; `scope_restricted` means the verified Azure scope is narrower than the endpoint's intended scope; and `visibility_unverified` means that the available evidence could not prove complete visibility. Failed or incomplete role, definition, group or deny-assignment inspection remains unverified. Delegated Graph scopes, specialised Azure actions, service data-plane operations and unmapped permissions also remain unverified rather than being inferred from an empty response.
- Record counts use the semantic collection within common Azure and Graph wrappers. For example, `{"value": []}` is zero records, while a singleton policy object is one record.
- Resource-scoped diagnostic settings are requested only after Azure confirms that the resource exposes diagnostic-setting categories. Azure responses with `ResourceTypeNotSupported` are recorded as not applicable. A successful settings request that returns no records is retained as explicit evidence that the supported resource was assessed and has no resource-scoped diagnostic setting; unsupported and failed requests are not treated as missing settings.
- Retired Azure Data Lake Storage Gen1 and Azure Media Services endpoints are not requested. Private endpoint connections are queried by Azure resource ID, and Storage Queue CORS is collected from the Queue service-properties ARM endpoint.
- A manifest run status of `partial` means an endpoint failed, was unauthorised, encountered a tenant capability restriction or was not attempted, or the top-level workflow did not complete. Legitimately skipped endpoints remain visible individually. Skipped parameterised endpoints retain their immediate upstream endpoints, root-cause endpoints, contributing reason codes and dependency chains so that a direct request failure is not hidden by downstream omissions. Review `endpoint_runs`, `errors`, and `limitations` before treating an absent finding as evidence of a secure configuration. Manifest schema versions 2.0 through 2.4 remain readable; ARM access claims from schema 2.4 are treated as unverified because that revision did not inspect deny assignments.
- Manifest command entries use configured command templates rather than reconstructed shell commands, while context, options, parameter values, limitations, and recorded error content are preserved without content filtering. Endpoint error fields are limited to 1,000 characters. Raw Azure CLI output is not duplicated into successful manifest entries because it remains in the generated dataset; failed-command diagnostic output is recorded as the endpoint error. Manifests may therefore contain credentials or other sensitive engagement data and must be protected accordingly.
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
- `-o`, `--output-file`: path for the SARIF 2.1.0 findings output. Relative paths are resolved below `<input-dir>`. Default: `<input-dir>/azure-findings-SARIF.json`
- `--no-save`: do not write findings JSON files; print summary output only
- `--flat-output-file`: path for the flattened findings output used by `azure-present.py`. Relative paths are resolved below `<input-dir>`. Default: `<input-dir>/azure-findings-flat.json`
- `--report-ready-output-file`: path for the versioned report-ready findings export. Relative paths are resolved below `<input-dir>`. Default: `<input-dir>/azure-findings-report-ready.json`
- `--review-file`: optional versioned JSON file containing analyst review overrides keyed by canonical `finding_id`. Relative paths are resolved below `<input-dir>`
- `--baseline-findings-file`: optional prior `azure-findings-flat.json` used for conservative retest comparison. Relative paths are resolved below `<input-dir>`

Outputs:

- `azure-findings-SARIF.json`: SARIF 2.1.0 output containing the full set of findings in the `found` state
- `azure-findings-flat.json`: flattened findings rows for easier dashboard display
- `azure-findings-report-ready.json`: version 2.0 compact report-processing export containing selected findings, publication readiness, report groups, and auditable exclusions

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
- The diagnostic-settings check uses only resources whose diagnostic-setting endpoint was successfully assessed as its eligible population. A supported resource with a successful empty response is raised as unconfigured; unsupported, unauthorised and failed resource requests remain outside that finding rather than becoming false positives.
- Critical-resource lock analysis applies `ReadOnly` and `CanNotDelete` locks inherited from subscription and resource-group scopes. Eligibility is limited to the versioned critical-resource profile, and a missing lock is reported only when lock collection is complete.
- Azure Policy analysis selects the latest resource/assignment/definition state, excludes compliant, exempt, and not-applicable records, separates explicit evaluation errors from non-compliance, and compares enforced assignments with the versioned Microsoft cloud security benchmark expectation. Missing assignments require a complete assignment inventory, while evaluation-error conclusions require both Policy states and events. The benchmark initiative identifier is documented by [Microsoft's Azure Policy built-in index](https://learn.microsoft.com/azure/governance/policy/samples/).
- Active Azure Advisor security recommendations are correlated with Defender assessments using exact resource and control identifiers first. Strong title similarity is retained as an explicitly inferred match and never suppresses unmatched evidence.
- Public-network settings are correlated with approved, successfully provisioned private endpoint connections for Storage, Key Vault, Container Registry, App Service, App Configuration, Application Gateway, Cosmos DB, Machine Learning, and Azure AI Search. A private endpoint is not treated as removing exposure while public access remains enabled.
- Application registrations, service principals, managed identities, groups, role assignments, and role definitions are correlated to identify privileged non-human principals at tenant, management-group, and subscription scopes. Credential expiry uses the collection completion time and emits metadata only; group membership is declared unavailable because it is not collected.
- Internet ingress analysis follows assigned public IPs through direct NICs, load-balancer rules and Application Gateway listeners to resolved backends. NSG decisions apply first-match priority across source address sets, the translated backend destination and port, Azure default inbound deny, and the intersection of effective NIC/subnet layers. Unknown NSG decisions do not establish reachability; effective route data is supporting evidence rather than proof of service exploitability.

Analyst review:

- Found checks default to an `unreviewed` `candidate` disposition and remain included for report-ready processing. Candidates are not silently excluded merely because an analyst has not reviewed them yet.
- The findings view in `azure-present.py` provides a **Validated** checkbox for every raised finding. Enter the analyst's name before changing a checkbox; the UI records a `confirmed` disposition and a server-generated UTC review time in `<input-dir>/azure-findings-review.json`. Clearing the checkbox records a reviewed `candidate` disposition. Existing analyst confidence, contextual severity and notes are preserved.
- **Export Validated SARIF** downloads `azure-findings-validated-SARIF.json` containing only current `found` results whose effective disposition is `confirmed`. The export is independent of the visible status and search filters, retains each result's evidence, and replaces its embedded review metadata with the current persisted review. The source `azure-findings-SARIF.json` must remain alongside the flat findings file.
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
- The export does not copy legacy raw `evidence`; it emits canonical normalised observations while retaining exact duplicate accounting. Engagement context, observation data, reference links, report narratives, analyst rationale, and notes are copied without content filtering or size-based substitution.
- Report-ready exports may therefore contain credentials, tokens, keys, signed URLs, private keys, or other sensitive engagement data present in collected evidence or analyst-authored content. Store, transmit, and dispose of these files according to the engagement's sensitive-data handling requirements.

### `azure-present.py`

Purpose:
Run a local web interface for browsing the collected datasets and findings output. The dashboard now groups timestamped dataset versions and defaults to the latest collected snapshot for each dataset type.

In the findings table, the Definition, Reporting, Context, Coverage, Review and Triage columns are concise operational summaries rather than complete schema objects. Use **View JSON** on a row to inspect the original finding, including all schema metadata, provenance, evidence relationships, rationale, identifiers and retest detail.

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
- Analyst confirmations made in the findings view are stored atomically in `azure-findings-review.json` with owner-only file permissions. Keep this sidecar with the assessment data. To incorporate those decisions when regenerating all findings outputs, run `azure-findings.py` with `--review-file azure-findings-review.json`.
- Data Viewer normalises collected JSON into horizontal rows: singleton objects appear as one row, Microsoft Graph `value` envelopes expose their individual records, and flat lists or scalar values receive explicit index/value columns. Search filters those normalised records rather than filtering wrapper fields.
- The dashboard uses one pie chart for mutually exclusive finding-check outcomes. Checks without sufficient data are divided by one primary cause from their required endpoint provenance: unauthorised source, unavailable tenant licence or capability, failed request, interrupted or unrecorded collection, skipped prerequisite, empty upstream source, or missing/unattributed source. These cause slices add back to the total number of inconclusive checks. Azure request statistics use a different denominator and are therefore shown as cards and tables rather than mixed into that chart.
- Failed, unauthorised and tenant-restricted Azure requests are reported directly from the latest collection manifest. The failure table shows the endpoint, request category, parameter context, Azure error code, Azure CLI return code, and returned error message. Empty responses are split into access verified, scope restricted and visibility unverified counts. These statistics are independent of the permission-baseline warning and do not infer how many finding checks were affected.
- A collapsed endpoint-omission table groups deliberately skipped endpoints and planned endpoints without a recorded outcome by their operational reason. Dashboard cards separately count skipped endpoints caused by unauthorised, tenant-restricted, empty and other prerequisites. New manifests preserve those causes through multi-level endpoint dependencies and also distinguish upstream failures, unusable parameters, collector configuration defects, interruptions, exceptions, and missing collector instrumentation. Older manifests remain readable and are labelled when the original reason was not recorded.

## Example End-to-End Usage

```bash
mkdir -p ~/azure-collect-data
pipenv run python azure-collect.py -o ~/azure-collect-data
pipenv run python azure-findings.py -i ~/azure-collect-data
pipenv run python azure-present.py -i ~/azure-collect-data
```

Then open `http://127.0.0.1:5000/` in a browser.

## Microsoft Graph workload collection

The default collection uses the native Graph runner for Microsoft Graph work across Identity Baseline, Entra directory/group PIM, Microsoft 365 Audit, Endpoint/Intune, Global Secure Access and Defender Hunting. Older `az ad` and Graph-targeted `az rest` collection paths are retained only as historical dataset mappings; new collection no longer depends on their delegated-token behaviour. Inventory endpoints collect every available page. Activity, audit and hunting data use a resolved UTC interval controlled by `--graph-lookback-days` (30 days by default); the exact start and end are recorded in the schema 2.5 collection manifest.

The permission profiles have three capability classes: stable inventory reads, time-bounded activity/audit reads, and explicitly beta-dependent reads. Security Defaults, sign-ins, provisioning logs, identity providers, directory PIM and group PIM use stable v1.0 Graph APIs. Azure-resource PIM uses stable Azure Resource Manager `Microsoft.Authorization` schedule APIs instead of Graph. Microsoft 365 D30 usage reports use stable Graph report functions, while the 30-day unified audit query remains beta because the non-Graph Management Activity API exposes only a seven-day retrieval window. Recommendations, Global Secure Access and Defender for Identity resources remain visibly labelled beta where Microsoft has no stable equivalent. Defender hunting remains on Graph because it replaces the retiring workload-specific hunting APIs. A missing licence or unavailable capability is recorded as unavailable and does not become a configuration absence finding.

Datasets use stable `graph_<profile>_<dataset>_<timestamp>.json` names. Records include `_collectionContext` provenance. Endpoints that require Microsoft Graph beta are explicitly labelled in the manifest limitations. Unauthorised requests, unavailable tenant/licence capabilities, inapplicable endpoints, failures and incomplete collection remain distinct assessment states.

Use `--endpoint` with a friendly endpoint name, stable Graph endpoint ID, profile, permission or URL fragment. BitLocker collection requests metadata only and never requests recovery key material. The built-in Defender query pack is fixed and versioned; missing tables or licences affect only the relevant query.

Security Defaults remains available at the stable `/v1.0/policies/identitySecurityDefaultsEnforcementPolicy` endpoint and requires the `Policy.Read.All` application permission. An `AccessDenied` result means the acquired Graph token lacks a suitable permission; it does not mean that Microsoft removed the REST API. The native runner preserves the supplied Graph error code and message so licence restrictions and missing permissions remain distinguishable.
