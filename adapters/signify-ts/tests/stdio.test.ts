// Runs the real launcher as a child process, the way the runner does: a scrubbed environment and
// the runner's 4 GiB address-space limit when prlimit is available to impose it.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const launcher = fileURLToPath(new URL('../bin/kcs-adapter-signify-ts', import.meta.url));
const env = { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '' };
const ADDRESS_SPACE = String(4 * 1024 ** 3);
const hasPrlimit = spawnSync('prlimit', ['--version']).status === 0;

function session(input: string, limited: boolean) {
    const [cmd, args] = limited
        ? ['prlimit', [`--as=${ADDRESS_SPACE}`, '--', launcher]]
        : [launcher, []];
    return spawnSync(cmd, args as string[], { input, env, encoding: 'utf8', timeout: 60_000 });
}

const script = [
    JSON.stringify({ id: 0, op: 'hello', protocol: 1, supported: [1] }),
    JSON.stringify({ id: 1, op: 'cesr.encode', code: 'E', raw: '00'.repeat(32), domain: 'text' }),
    '',
].join('\n');

describe('the launcher', () => {
    it('answers over stdio and exits 0 at end of input', () => {
        const run = session(script, false);
        expect(run.stderr).toBe('');
        expect(run.status).toBe(0);
        const lines = run.stdout.trim().split('\n').map((l) => JSON.parse(l));
        expect(lines.map((l) => l.id)).toEqual([0, 1]);
        expect(lines[0].result.implementation.name).toBe('signify-ts');
        expect(lines[1].result.encoded).toBe(Buffer.from('E' + 'A'.repeat(43)).toString('hex'));
    });

    it.runIf(hasPrlimit)('starts libsodium under the runner\'s 4 GiB address-space limit', () => {
        const run = session(script, true);
        expect(run.stderr).toBe('');
        expect(run.status).toBe(0);
        expect(run.stdout.trim().split('\n')).toHaveLength(2);
    });
});
