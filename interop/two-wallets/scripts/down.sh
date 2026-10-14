#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
nice -n 19 ionice -c 3 docker compose -f "$root/compose.yaml" down -v
