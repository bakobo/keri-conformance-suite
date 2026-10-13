#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
"$root/scripts/down.sh"
rm -f "$root/out/verifier.json" "$root/out/m3-veridian.json" "$root/out/m3-heti.json" \
  "$root/out/m4.json" "$root/out/heti-delivery.json" "$root/out/verifier-error.txt" \
  "$root/out/verifier-holder-ready" "$root/out/export.json" \
  "$root/out/export-credential.cesr" "$root/out/heti-holder.json" \
  "$root/out/heti-grant.cesr" "$root/out/admit-behavior.log"
rm -f "$root/out/m3-veridian-admit.json" "$root/out/m3-veridian-admit-check.json"
rm -rf "$root/out/heti-holder"
"$root/scripts/up.sh"
G17_NO_FIXTURES=1 nice -n 19 ionice -c 3 "$root/veridian-driver/bin/veridian" m2
nice -n 19 ionice -c 3 /home/daniel/code/bakobo/heti/.worktrees/two-wallets/.venv/bin/python \
  "$root/py/fetch_kel.py" "$root/out/m1.json"
set +e
nice -n 19 ionice -c 3 "$root/veridian-driver/bin/veridian" m3
result=$?
set -e
nice -n 19 ionice -c 3 docker compose -f "$root/compose.yaml" logs --no-color keria \
  | sed 's/[[:blank:]]*$//' > "$root/out/keria-m3.log"
for required in m3-heti.json m4.json; do
  if [[ ! -f "$root/out/$required" ]]; then
    echo "Required M3/M4 result is missing: $required" >&2
    result=1
  fi
done
# Incompatibility 14 is an expected observation, not a failure of the run: the holder AID's only
# published agent end role is still Veridian's KERIA agent, so the verifier's admit of heti's grant
# is routed there, where no such grant exists. The run fails only if that observation changes,
# because then the writeup is stale.
if [[ "$result" -eq 0 ]]; then
  admit_said=$(node -e 'console.log(require(process.argv[1]).admit_said)' "$root/out/m3-heti.json")
  holder=$(node -e 'console.log(require(process.argv[1]).holder_aid_in_heti)' "$root/out/m4.json")
  veridian_agent=$(node -e 'console.log(require(process.argv[1]).keriaAgentPre)' "$root/out/m1.json")
  grep -F "said=$admit_said" "$root/out/keria-m3.log" | grep -F 'failed behavior verfication' \
    > "$root/out/admit-behavior.log" || true
  curl -fsS --max-time 5 "http://127.0.0.1:3902/oobi/$holder/agent" \
    | grep -o '"role":"agent","eid":"[^"]*"' > "$root/out/holder-agent-role.txt" || true
  if [[ -s "$root/out/admit-behavior.log" ]] && grep -qF "\"eid\":\"$veridian_agent\"" "$root/out/holder-agent-role.txt"; then
    echo "Incompatibility 14 observed as recorded: the verifier's admit of heti's grant went to Veridian's agent."
  else
    echo "Incompatibility 14 did not reproduce as recorded; update INCOMPATIBILITIES.md." >&2
    result=1
  fi
fi
exit "$result"
