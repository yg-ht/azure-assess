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

Notes:

- The script expects the Azure CLI to be installed and available on `PATH`.
- On first use it will prompt for Azure authentication using the Azure CLI login flow.
- Output files are timestamped in their filenames, which is used by the dashboard to track dataset history.

### `azure-findings.py`

Purpose:
Analyse the JSON produced by `azure-collect.py` and generate structured findings describing confirmed issues, checks that did not find evidence, and checks that are not yet implemented or evaluated.

Typical usage:

```bash
pipenv run python azure-findings.py -i ~/azure-collect-data
```

Parameters:

- `-i`, `--input-dir`: directory containing JSON produced by `azure-collect.py`. Default: `azure-collect`
- `-o`, `--output-file`: path for the structured findings JSON output. Default: `<input-dir>/azure-findings.json`
- `--no-save`: do not write findings JSON files; print summary output only
- `--flat-output-file`: path for the flattened findings output used by `azure-present.py`. Default: `<input-dir>/azure-findings-flat.json`

Outputs:

- `azure-findings.json`: structured findings output
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
