// Process entry point; bin/kcs-adapter-signify-ts starts it. libsodium must be ready before the
// first request, and the adapter exits 0 when the runner closes standard input.
import { once } from 'node:events';

import { ready } from 'signify-ts';

import { serve } from './protocol.ts';

await ready();
await serve(process.stdin, async (line) => {
    if (!process.stdout.write(line)) {
        await once(process.stdout, 'drain');
    }
});
