// Process entry point; bin/kcs-adapter-signify-keria starts it. libsodium must be ready before the
// first request. The session's KERIA container is removed whenever the process exits, including on
// a signal; the adapter exits 0 when the runner closes standard input.
import { once } from 'node:events';

import { ready } from 'signify-ts';

import { stopKeria } from './keria.ts';
import { serve, session } from './protocol.ts';

await ready();
let container: string | undefined;
const deps = session((keria) => {
    container = keria.container;
    process.stderr.write(`kcs-adapter-signify-keria: started ${keria.image} as container ${keria.container}\n`);
});
process.on('exit', () => {
    if (container !== undefined) {
        stopKeria(container);
    }
});
for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) {
    process.on(signal, () => process.exit(1));
}
await serve(
    process.stdin,
    async (line) => {
        if (!process.stdout.write(line)) {
            await once(process.stdout, 'drain');
        }
    },
    deps,
);
process.exit(0);
