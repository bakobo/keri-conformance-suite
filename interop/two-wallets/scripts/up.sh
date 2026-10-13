#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
"$root/scripts/build-keria.sh"
nice -n 19 ionice -c 3 docker compose -f "$root/compose.yaml" up -d
oobis=(
  'BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha'
  'BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM'
  'BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX'
  'BM35JN8XeJSEfpxopjn5jr7tAHCE5749f0OobhMLCorE'
  'BIj15u5V11bkbtAxMA7gcNJZcax-7TgaBMLsQnMHpYHP'
  'BF2rZTW79z4IXocYRQnjjsOuvFUQv-ptCf8Yltd7PfsM'
)
index=0
for port in 5642 5643 5644 5645 5646 5647; do
  ready=0
  for _ in $(seq 1 120); do
    if curl -fsS --max-time 2 "http://127.0.0.1:$port/oobi/${oobis[index]}/controller?role=witness" >/dev/null 2>&1; then ready=1; break; fi
    sleep 1
  done
  if [[ "$ready" -ne 1 ]]; then echo "Witness OOBI port $port did not become ready" >&2; exit 1; fi
  index=$((index + 1))
done
ready=0
for _ in $(seq 1 120); do
  if curl -sS --max-time 2 -o /dev/null "http://127.0.0.1:3903/boot"; then ready=1; break; fi
  sleep 1
done
if [[ "$ready" -ne 1 ]]; then echo "KERIA boot port 3903 did not become ready" >&2; exit 1; fi
echo 'Six witness OOBI ports and KERIA boot port are reachable.'
