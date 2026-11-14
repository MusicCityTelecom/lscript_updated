#!/usr/bin/env bash
set -euo pipefail
source_path="$(readlink -f -- "${BASH_SOURCE[0]}")"
project_dir="$(CDPATH='' cd -- "$(dirname -- "$source_path")" && pwd)"
exec python3 "$project_dir/lazy.py" "$@"
