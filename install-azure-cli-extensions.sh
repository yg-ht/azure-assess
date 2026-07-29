#!/usr/bin/env bash

set -euo pipefail

if ! command -v az >/dev/null 2>&1; then
    echo "[ERROR] Azure CLI is not installed or is not available on PATH." >&2
    exit 1
fi

azure_extension_dir="${AZURE_EXTENSION_DIR:-$PWD/.azure-cliextensions}"
current_directory="$(pwd -P)"

if [[ -z "$azure_extension_dir" ]]; then
    echo "[ERROR] Refusing to use an unsafe Azure CLI extension directory." >&2
    exit 1
fi

mkdir -p "$azure_extension_dir"
azure_extension_dir="$(cd -- "$azure_extension_dir" && pwd -P)"

if [[ \
    "$azure_extension_dir" == "/" \
    || "$azure_extension_dir" == "$current_directory" \
    || "$azure_extension_dir" == "${HOME:-}" \
]]; then
    echo "[ERROR] Refusing to use an unsafe Azure CLI extension directory: $azure_extension_dir" >&2
    exit 1
fi

readonly azure_extension_dir
readonly current_directory
readonly -a azure_extensions=(
    application-insights
    bastion
    databricks
    datafactory
    ml
)

export AZURE_EXTENSION_DIR="$azure_extension_dir"

echo "[*] Using Azure CLI:"
az version --output jsonc

echo "[*] Using extension directory: $AZURE_EXTENSION_DIR"

for extension_name in "${azure_extensions[@]}"; do
    echo "[*] Removing extension: $extension_name"
    az extension remove \
        --name "$extension_name" \
        --only-show-errors >/dev/null 2>&1 || true
    rm -rf -- "$AZURE_EXTENSION_DIR/$extension_name"
done

az config set extension.use_dynamic_install=no --only-show-errors >/dev/null

for extension_name in "${azure_extensions[@]}"; do
    echo "[*] Installing extension: $extension_name"
    az extension add \
        --name "$extension_name" \
        --yes \
        --only-show-errors
done

echo "[*] Installed extensions:"
az extension list \
    --query "[].{name:name,version:version,path:path}" \
    --output table

echo "[*] Verifying Azure ML command group:"
az ml --help >/dev/null

echo "[OK] Azure CLI extensions reinstalled cleanly and az ml loads"
