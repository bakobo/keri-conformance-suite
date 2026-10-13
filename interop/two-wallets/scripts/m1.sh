#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
"$root/scripts/up.sh"
nice -n 19 ionice -c 3 "$root/veridian-driver/bin/veridian" m1
nice -n 19 ionice -c 3 /home/daniel/code/bakobo/heti/.worktrees/two-wallets/.venv/bin/python "$root/py/fetch_kel.py" "$root/out/m1.json"
nice -n 19 ionice -c 3 "$root/veridian-driver/bin/vectors"
