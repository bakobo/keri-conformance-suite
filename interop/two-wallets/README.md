# G17 two-wallet interop, milestone M1

This is a live observation of pinned implementations, not a conformance verdict. M1 starts the six witnesses used by Veridian, boots Veridian's own `src/core` in a Node process, creates a witnessed holder AID, and checks the witness's KERI 1.x CESR with heti's keripy fork. It does not yet issue or present an ACDC.

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

See [INCOMPATIBILITIES.md](INCOMPATIBILITIES.md) for the seams observed in M1.
