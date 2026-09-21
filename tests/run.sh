#!/usr/bin/env bash
set -euo pipefail

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHONPATH="$root_dir/src" exec python3 -m unittest discover -s "$root_dir/tests" -p 'test_*.py' -v
