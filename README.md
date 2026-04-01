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
apt install azure-cli pipenv
git clone https://github.com/yg-ht/azure-assess.git
cd azure-assess
pipenv install -r requirements.txt
```

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
- `--auth-method`: authentication mode for Azure CLI. Supported values: `existing`, `device-code`, `browser`, `service-principal`, `managed-identity`. Default: `existing`
- `--tenant-id`: Azure tenant ID for login and/or context selection. Defaults to `AZURE_TENANT_ID`
- `--subscription-id`: Azure subscription ID to select after authentication. Defaults to `AZURE_SUBSCRIPTION_ID`
- `--client-id`: service principal or user-assigned managed identity client ID. Defaults to `AZURE_CLIENT_ID`
- `--client-secret`: service principal client secret. Defaults to `AZURE_CLIENT_SECRET`
- `--client-certificate`: certificate path for service principal auth. Defaults to `AZURE_CLIENT_CERTIFICATE_PATH`
- `--client-certificate-password`: certificate password for service principal auth. Defaults to `AZURE_CLIENT_CERTIFICATE_PASSWORD`

Notes:

- The script expects the Azure CLI to be installed and available on `PATH`.
- The default authentication mode is `existing`, which reuses the current Azure CLI session and does not trigger a login flow.
- If `--auth-method existing` is used and no valid Azure CLI session is present, the tool exits with guidance instead of forcing device code authentication.
- Authentication validation checks both the current Azure account context and token acquisition for Azure Resource Manager and Microsoft Graph before collection starts.
- `--subscription-id` applies the Azure CLI account context after authentication and can also be supplied through `AZURE_SUBSCRIPTION_ID`.
- Output files are timestamped in their filenames, which is used by the dashboard to track dataset history.

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
Analyse the JSON produced by `azure-collect.py`, print a status summary for all implemented checks, and generate SARIF output for the confirmed findings.

Typical usage:

```bash
pipenv run python azure-findings.py -i ~/azure-collect-data
```

Parameters:

- `-i`, `--input-dir`: directory containing JSON produced by `azure-collect.py`. Default: `azure-collect`
- `-o`, `--output-file`: path for the SARIF 2.1.0 findings output. Default: `<input-dir>/azure-findings.json`
- `--no-save`: do not write findings JSON files; print summary output only
- `--flat-output-file`: path for the flattened findings output used by `azure-present.py`. Default: `<input-dir>/azure-findings-flat.json`

Outputs:

- `azure-findings.json`: SARIF 2.1.0 output containing the full set of confirmed findings
- `azure-findings-flat.json`: flattened findings rows for easier dashboard display

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
