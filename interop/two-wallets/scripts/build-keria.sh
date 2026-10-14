#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
source_dir="$root/.ignored/keria-src"
pin=bca7accb633398e16fa247b140de91c95a342aed
tag=g17/keria:bca7acc
if docker image inspect "$tag" >/dev/null 2>&1; then
  echo "$tag already exists; skipping build"
  exit 0
fi
if [[ ! -d "$source_dir/.git" ]]; then
  git clone https://github.com/cardano-foundation/keria.git "$source_dir"
fi
git -C "$source_dir" fetch origin "$pin"
git -C "$source_dir" checkout --detach "$pin"
nice -n 19 ionice -c 3 docker build -f "$source_dir/images/keria.dockerfile" -t "$tag" "$source_dir"
