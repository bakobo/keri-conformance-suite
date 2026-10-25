// Runs the real launcher as a child process, the way the runner does: a scrubbed environment and
// the runner's 4 GiB address-space limit when prlimit is available to impose it. Without
// KCS_KERIA_LIVE=1 it sends nothing that starts KERIA; with it, a hello starts the pinned image in
// Docker and the container must be gone once the launcher exits. Starting Node and libsodium can
// pass vitest's 5-second default on a loaded machine, so each spawn is allowed 30 seconds.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const launcher = fileURLToPath(new URL('../bin/kcs-adapter-signify-keria', import.meta.url));
const env = { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '' };
const ADDRESS_SPACE = String(4 * 1024 ** 3);
const hasPrlimit = spawnSync('prlimit', ['--version']).status === 0;
const live = process.env.KCS_KERIA_LIVE === '1';

function session(input: string, limited: boolean) {
    const [cmd, args] = limited ? ['prlimit', [`--as=${ADDRESS_SPACE}`, '--', launcher]] : [launcher, []];
    return spawnSync(cmd, args as string[], { input, env, encoding: 'utf8', timeout: 120_000 });
}

const lines = (...requests: unknown[]) => requests.map((r) => JSON.stringify(r)).join('\n') + '\n';

describe('the launcher', () => {
    it('answers over stdio and exits 0 at end of input', () => {
        const run = session(lines({ id: 0, op: 'nope' }, { id: 1, op: 'keri.process' }), false);
        expect(run.stderr).toBe('');
        expect(run.status).toBe(0);
        expect(run.stdout.trim().split('\n').map((l) => JSON.parse(l).id)).toEqual([0, 1]);
    }, 30_000);

    it.runIf(hasPrlimit)('starts libsodium under the runner\'s 4 GiB address-space limit', () => {
        const run = session(lines({ id: 0, op: 'nope' }), true);
        expect(run.status).toBe(0);
        expect(run.stdout.trim().split('\n')).toHaveLength(1);
    }, 30_000);

    it.runIf(live && hasPrlimit)('starts KERIA under that limit and removes it on exit', () => {
        const run = session(lines({ id: 0, op: 'hello', supported: [1] }), true);
        expect(run.status).toBe(0);
        const hello = JSON.parse(run.stdout.trim());
        expect(hello.result.implementation.version).toMatch(/with KERIA 0\.4\.1 \(keripy 1\.2\.14\)$/);
        const container = /as container ([0-9a-f]{64})/.exec(run.stderr)?.[1];
        expect(container).toBeDefined();
        expect(spawnSync('docker', ['ps', '-aq', '--filter', `id=${container}`], { encoding: 'utf8' }).stdout.trim()).toBe('');
    }, 120_000);
});
