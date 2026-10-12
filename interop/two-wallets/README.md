# G17 two-wallet interop, milestones M1 and M2

This is a live observation of pinned implementations, not a conformance verdict. M1 starts the six witnesses used by Veridian, boots Veridian's own `src/core` in a Node process, creates a witnessed holder AID, and checks the witness's KERI 1.x CESR with heti's keripy fork. M2 creates a separate issuer on the same KERIA, issues a SEDI-shaped 1.x ACDC, grants it over IPEX, and admits it through Veridian's core.

## Pins and prerequisites

| Component | Pin |
| --- | --- |
| Veridian | `d41ce8811f790b9883176539794e68d36fa66bba` |
| signify-ts | `62a646f1eb67c30c8f1aecfe628d81dd693b60f2` (Veridian lockfile) |
| KERIA | `bca7accb633398e16fa247b140de91c95a342aed`, built as `g17/keria:bca7acc` |
| Witness image | `weboftrust/keri:1.1.26` |
| heti | `/home/daniel/code/bakobo/heti/.worktrees/two-wallets` and its `.venv` |
| Runtime | Node 24, Docker Compose, Python from heti's venv |

The KERIA build script checks for `g17/keria:bca7acc` first. If absent, it clones the pinned source into the repository's `.ignored/keria-src` and builds `images/keria.dockerfile`. The services use host networking. Ports 5642–5647 belong to witnesses and 3901–3903 to KERIA; make sure they are free.

Set up a separate Veridian checkout and install its exact lockfile dependencies:

```sh
git -C /home/daniel/code/bakobo/veridian-wallet worktree add /home/daniel/code/bakobo/veridian-wallet/.worktrees/two-wallets -b two-wallets d41ce881
cd /home/daniel/code/bakobo/veridian-wallet/.worktrees/two-wallets
nice -n 19 ionice -c 3 npm ci
```

If that worktree already exists, keep it and run only `npm ci`. Set `VERIDIAN_DIR` to another pinned checkout if needed. The full install is necessary because signify-ts is a Git dependency with a prepare build.

From this repository worktree:

```sh
nice -n 19 ionice -c 3 interop/two-wallets/scripts/down.sh
nice -n 19 ionice -c 3 interop/two-wallets/scripts/m1.sh
```

`m1.sh` starts the services, waits for every witness OOBI and KERIA's boot port, runs `veridian m1`, fetches the holder's KEL with heti's Python, and generates derivation vectors. Node 24 strips types from the CLI launcher; esbuild bundles Veridian's legacy-decorator core with the local module shims. The driver calls Veridian's `Agent`, `IonicSession`, `IdentifierService`, and notification/operation pollers in process. Its `out/m1.json` contains the bran and mnemonic, so handle it as wallet recovery material. `out/m1-kel.cesr` is the exact witness response. `vectors/signify-salty-62a646f.json` contains three offline salty vectors and one witnessed vector from the M1 run. Since signify-ts creates a fresh per-AID salt, regenerating offline vectors changes `sxlt` and the derived AID while preserving the fixed brans and derivation path.

Run the offline vector generator alone with `nice -n 19 ionice -c 3 interop/two-wallets/veridian-driver/bin/vectors`. Stop and reset the services with `nice -n 19 ionice -c 3 interop/two-wallets/scripts/down.sh`. This removes the named Docker volumes.

## M2: issue and hold

```sh
nice -n 19 ionice -c 3 interop/two-wallets/scripts/m2.sh
```

`m2.sh` first resets the volumes, starts the M1 services, then runs M1 creation and M2 admission **in one Node process** with `veridian m2`. This preserves Veridian's fake IndexedDB and secure-storage state until admission finishes. It then runs the M1 witness KEL check. The issuer CLI runs as a child process and serves the generated schema at `http://127.0.0.1:7723/oobi/<schema-said>` during the grant. The holder's issuer connection and schema OOBI resolution complete before the issuer sends the grant.

`schemas/sedi-core-1x.schema.json` keeps the SAM core attribute section unchanged and uses the 1.x top-level ACDC fields. Its keripy `Schemer` SAID is `EP3O5QNAho8Z7B9TTTdHWK7Ge_sPgZciw8Y4tYjpITqY`. `out/m2.json` records the credential, issuer, registry, schema, and holder identifiers. `fixtures/m2/credential.cesr` is the exact holder-agent CESR response; `holder-kel.cesr` and `issuer-kel.cesr` are the exact witness responses; `holder.json` contains the holder bran, `sxlt`, and AID. These fixtures include wallet recovery material and are intended for heti's interop tests.

The issuer uses the pinned signify-ts client and signing primitives. Its `credentials().issue` helper inserts `a.dt`, which the unchanged SAM attribute schema rejects; the local issuer path submits the same signed 1.x events without that field. The driver also bridges two Veridian core assumptions about this schema during admission, without editing Veridian. See [INCOMPATIBILITIES.md](INCOMPATIBILITIES.md) for evidence and ownership of every observed seam.
