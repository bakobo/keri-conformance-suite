import { execFileSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

import { DEFAULT_START, KERIA_IMAGE, type Keria, SCHEMA_SERVER, START_DEADLINE, type StartDeps, runner, serveSchemas, startKeria, stopKeria } from '../src/keria.ts';

const PORTS: Record<string, string> = { '3901/tcp': '127.0.0.1:41', '3902/tcp': '127.0.0.1:42', '3903/tcp': '127.0.0.1:43', '7700/tcp': '127.0.0.1:44' };

function fake(options: { port?: string; fail?: string; answers?: boolean[] } = {}) {
    const calls: string[][] = [];
    const stopped: string[] = [];
    const answers = [...(options.answers ?? [])];
    let clock = 0;
    const deps: StartDeps = {
        async docker(args) {
            calls.push(args);
            if (args[0] === options.fail) {
                throw new Error(`${args[0]} broke`);
            }
            if (args[0] === 'run') return 'cid\n';
            if (args[0] === 'port') return `${options.port ?? PORTS[args[2]]}\n[::1]:9\n`;
            if (args.includes('-d')) return '';
            return '0.4.1 1.2.14\n';
        },
        async fetch() {
            const next = answers.length > 0 ? answers.shift() : true;
            if (next === undefined) throw new Error('refused');
            return new Response(null, { status: next ? 200 : 503 });
        },
        async sleep(ms) {
            clock += ms;
        },
        now: () => clock,
        stop: (container) => stopped.push(container),
    };
    return { deps, calls, stopped };
}

describe('startKeria', () => {
    it('starts the pinned image on loopback ports and reads its versions', async () => {
        const { deps, calls } = fake({ answers: [false, true, true] });
        const keria = await startKeria(deps);
        expect(keria).toEqual({
            container: 'cid',
            image: KERIA_IMAGE,
            admin: 'http://127.0.0.1:41',
            http: 'http://127.0.0.1:42',
            boot: 'http://127.0.0.1:43',
            schemas: 'http://127.0.0.1:44',
            keria: '0.4.1',
            keri: '1.2.14',
        });
        const run = calls[0];
        expect(run.slice(0, 3)).toEqual(['run', '-d', '--rm']);
        expect(run.filter((a, i) => run[i - 1] === '-p')).toEqual(['127.0.0.1::3901', '127.0.0.1::3902', '127.0.0.1::3903', '127.0.0.1::7700']);
        expect(run.slice(-2)).toEqual([KERIA_IMAGE, 'start']);
        expect(calls[1]).toEqual(['exec', '-d', 'cid', '/keria/.venv/bin/python', '-c', SCHEMA_SERVER]);
    });

    it('waits through a fetch that cannot connect', async () => {
        const { deps } = fake({ answers: [undefined as unknown as boolean] });
        expect((await startKeria(deps)).container).toBe('cid');
    });

    it('removes the container and fails when a port is not on loopback', async () => {
        const { deps, stopped } = fake({ port: '0.0.0.0:41' });
        await expect(startKeria(deps)).rejects.toMatchObject({
            kind: 'harness',
            message: expect.stringMatching(/^e\.env\.dependency\.keria-start\.t: .*not on 127\.0\.0\.1/),
        });
        expect(stopped).toEqual(['cid']);
    });

    it('removes the container when KERIA never answers', async () => {
        const { deps, stopped } = fake({ answers: Array(START_DEADLINE).fill(false) });
        await expect(startKeria(deps)).rejects.toMatchObject({ message: expect.stringMatching(/did not answer within 45 seconds/) });
        expect(stopped).toEqual(['cid']);
    });

    it('has nothing to remove when the container never started', async () => {
        const { deps, stopped } = fake({ fail: 'run' });
        await expect(startKeria(deps)).rejects.toMatchObject({ message: expect.stringMatching(/run broke/) });
        expect(stopped).toEqual([]);
    });
});

describe('the default parts', () => {
    it('run a program and report its standard output or its failure', async () => {
        expect(await runner('echo')(['hi'])).toBe('hi\n');
        await expect(runner('sh')(['-c', 'echo bad >&2; exit 3'])).rejects.toThrow(/sh -c failed: bad/);
        await expect(runner('false')([])).rejects.toThrow(/false undefined failed: Command failed/);
    });

    it('sleep, tell the time, fetch and stop', async () => {
        await DEFAULT_START.sleep(1);
        expect(DEFAULT_START.now()).toBeGreaterThan(0);
        await expect(DEFAULT_START.fetch('http://127.0.0.1:1/')).rejects.toThrow();
        expect(() => DEFAULT_START.stop('kcs-no-such-container')).not.toThrow();
    });
});

describe('stopKeria', () => {
    it('removes the container by force and never throws', () => {
        const seen: unknown[][] = [];
        stopKeria('cid', ((...args: unknown[]) => {
            seen.push(args);
            return Buffer.alloc(0);
        }) as unknown as typeof execFileSync);
        expect(seen[0].slice(0, 2)).toEqual(['docker', ['rm', '-f', 'cid']]);
        expect(() =>
            stopKeria('cid', (() => {
                throw new Error('no docker');
            }) as unknown as typeof execFileSync),
        ).not.toThrow();
    });
});

describe('serveSchemas', () => {
    const keria = { schemas: 'http://127.0.0.1:44' } as Keria;

    it('replaces the whole set with the request\'s schemas', async () => {
        let body = '';
        await serveSchemas(keria, new Map([['E1', '7b7d']]), async (_url, init) => {
            body = init?.body as string;
            return new Response(null, { status: 204 });
        });
        expect(JSON.parse(body)).toEqual({ E1: '7b7d' });
    });

    it('fails when the schema server refuses or is gone', async () => {
        await expect(serveSchemas(keria, new Map(), async () => new Response(null, { status: 500 }))).rejects.toMatchObject({
            message: expect.stringMatching(/^e\.env\.dependency\.keria\.t: .*HTTP 500/),
        });
        await expect(serveSchemas(keria, new Map(), async () => Promise.reject(new Error('reset')))).rejects.toMatchObject({
            message: expect.stringMatching(/reset/),
        });
        await expect(serveSchemas({ schemas: 'http://127.0.0.1:1' } as Keria, new Map())).rejects.toMatchObject({
            message: expect.stringMatching(/^e\.env\.dependency\.keria\.t: /),
        });
    });
});
