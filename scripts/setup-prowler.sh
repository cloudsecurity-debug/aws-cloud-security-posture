#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${HOME}/.venvs/prowler"

python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/python" -m pip install --upgrade pip
"${VENV_DIR}/bin/pip" install --no-cache-dir -r "${PROJECT_ROOT}/requirements.txt"

printf '\nProwler installation verified:\n'
"${VENV_DIR}/bin/prowler" --version
