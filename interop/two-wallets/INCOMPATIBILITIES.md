# M1 incompatibilities and runtime seams

The KERI 1.x holder inception fetched from a witness parsed and established key state with heti's KERI 2.0 keripy fork. The seams encountered while reaching that result follow.

1. **Writable KERI configuration files.** `interop/two-wallets/compose.yaml:12,24` mounts the witness directory and KERIA config read/write. With read-only mounts, `Configer` fell back to an empty configuration: `Configer(...).get()` printed `{}`, Veridian's `IdentifierService.getAvailableWitnesses()` raised `Misconfigured KERIA agent for this wallet type`, and KERIA logged `no http endpoint` for all six witnesses. The pinned KERIA `src/keria/app/agenting.py:301-305` opens `Configer` and the pinned keripy `Configer` uses `r+b`; Veridian's own compose also uses writable mounts. **Owner:** this harness's Compose configuration.

2. **Node test shim differs from a usable stream global.** Veridian `src/setupTests.ts:9-17` takes `ReadableStream` from `node:util` and assigns an object with an empty prototype. On Node 24, copying that literally caused `TypeError: ReadableStream is not a constructor` during `bootAndConnect`. `interop/two-wallets/veridian-driver/src/m1.ts:3-14` uses `node:stream/web` for the real constructor. **Owner:** this headless driver.

3. **Poller shutdown is a process boundary.** Veridian `src/core/agent/services/keriaNotificationService.ts:169-312,1090-1112` has `while (true)` loops; `stopPolling()` only sets `loggedIn = false`. The driver calls `stopPolling()` and unreferences only the poller timers, so its short-lived CLI exits naturally after writing output. **Owner:** Veridian core's poller lifecycle.

4. **The heti fork's `Baser` is not a context manager.** `with Baser(...)` in the first `fetch_kel.py` run raised `TypeError: 'keri.db.basing.Baser' object does not support the context manager protocol`. `interop/two-wallets/py/fetch_kel.py:24-36` now calls `close(clear=True)` in `finally`. **Owner:** this harness's Python integration.

5. **The pinned Signify package needs its prepare build.** `npm ci --ignore-scripts` left `node_modules/signify-ts/dist` absent, so the driver could not use the package entrypoint. A full `npm ci` in the separate Veridian worktree built it. **Owner:** this harness's installation instructions.

6. **Veridian declares a Node 20 engine.** The pinned `package.json:6` declares `20.x`, while this harness runs on Node 24. `npm ci` emitted `EBADENGINE`; the headless M1 run completed on Node 24 after the stream shim above. **Owner:** this harness's supported runtime choice.
