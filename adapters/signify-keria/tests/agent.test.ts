import { beforeAll, describe, expect, it } from 'vitest';
import { ready } from 'signify-ts';

import { type AgentDeps, type Client, DEFAULT_AGENT, WAIT, bootAgent, sentinel } from '../src/agent.ts';
import type { Keria } from '../src/keria.ts';

beforeAll(async () => {
    await ready();
});

const keria: Keria = {
    container: 'c',
    image: 'i',
    admin: 'http://127.0.0.1:1',
    http: 'http://127.0.0.1:2',
    boot: 'http://127.0.0.1:3',
    schemas: 'http://127.0.0.1:4',
    keria: '0.4.1',
    keri: '1.2.14',
};

interface Fake {
    agentPre?: unknown;
    boot?: () => Promise<Response>;
    resolve?: () => Promise<{ name: string }>;
    wait?: () => Promise<unknown>;
    states?: (() => Promise<unknown>)[];
    credential?: () => Promise<unknown>;
}

function client(fake: Fake): Client {
    const states = [...(fake.states ?? [])];
    return {
        agent: fake.agentPre === null ? null : { pre: (fake.agentPre ?? 'EAgent') as string },
        boot: fake.boot ?? (async () => new Response(null, { status: 202 })),
        connect: async () => {},
        oobis: () => ({ resolve: fake.resolve ?? (async () => ({ name: 'oobi.1' })) }),
        operations: () => ({ wait: fake.wait ?? (async () => ({ done: true })) }),
        keyStates: () => ({ get: async () => (states.length > 0 ? (states.shift() as () => Promise<unknown>)() : [{}]) }),
        credentials: () => ({ get: fake.credential ?? (async () => ({ sad: { d: 'E' } })) }),
    };
}

function deps(fake: Fake, put: (init: RequestInit) => Promise<Response> = async () => new Response(null, { status: 204 })) {
    const seen: RequestInit[] = [];
    let clock = 0;
    const d: AgentDeps = {
        client: () => client(fake),
        fetch: async (_url, init) => {
            seen.push(init as RequestInit);
            return put(init as RequestInit);
        },
        sleep: async (ms) => {
            clock += ms;
        },
        now: () => clock,
    };
    return { d, seen };
}

describe('sentinel', () => {
    it('is a signed 1.x inception of a fresh identifier', () => {
        const one = sentinel();
        const text = Buffer.from(one.message).toString('latin1');
        expect(text).toMatch(/^\{"v":"KERI10JSON[0-9a-f]{6}_","t":"icp"/);
        expect(text).toContain(`"i":"${one.pre}"`);
        expect(text).toMatch(/-AAB[A-Za-z0-9_-]{88}$/);
        expect(sentinel().pre).not.toBe(one.pre);
    });
});

describe('bootAgent', () => {
    it('makes a real signify-ts client by default, and sleeps, tells the time and fetches', async () => {
        expect(DEFAULT_AGENT.client(keria).constructor.name).toBe('SignifyClient');
        await DEFAULT_AGENT.sleep(1);
        expect(DEFAULT_AGENT.now()).toBeGreaterThan(0);
        await expect(DEFAULT_AGENT.fetch('http://127.0.0.1:1/')).rejects.toThrow();
    });

    it('refuses an agent that failed to boot', async () => {
        const { d } = deps({ boot: async () => Promise.reject(new Error('boot refused')) });
        await expect(bootAgent(keria, d)).rejects.toMatchObject({ message: expect.stringMatching(/^e\.env\.dependency\.keria\.t: .*boot refused/) });
    });

    it('refuses an agent without an identifier', async () => {
        const { d } = deps({ agentPre: null });
        await expect(bootAgent(keria, d)).rejects.toMatchObject({ message: expect.stringMatching(/without an agent identifier/) });
    });

    it('delivers bytes unchanged to its own agent', async () => {
        const { d, seen } = deps({});
        const agent = await bootAgent(keria, d);
        await agent.deliver(new Uint8Array([1, 2, 3]));
        expect(seen[0].method).toBe('PUT');
        expect((seen[0].headers as Record<string, string>)['CESR-DESTINATION']).toBe('EAgent');
        expect([...(seen[0].body as Buffer)]).toEqual([1, 2, 3]);
    });

    it('fails when KERIA refuses or cannot be reached', async () => {
        const refused = await bootAgent(keria, deps({}, async () => new Response('no', { status: 404 })).d);
        await expect(refused.deliver(new Uint8Array())).rejects.toMatchObject({ message: expect.stringMatching(/delivered a stream: HTTP 404/) });
        const gone = await bootAgent(keria, deps({}, async () => Promise.reject(new Error('reset'))).d);
        await expect(gone.deliver(new Uint8Array())).rejects.toMatchObject({ message: expect.stringMatching(/reset/) });
    });

    it('resolves a schema KERIA took, refuses one KERIA failed, and fails when KERIA does not answer', async () => {
        const ok = await bootAgent(keria, deps({}).d);
        expect(await ok.resolveSchema('u')).toBe(true);
        const refused = deps({ wait: async () => Promise.reject(new Error("Operation 'oobi.1' failed [Code 500]: resolving OOBI 1 failed")) });
        expect(await (await bootAgent(keria, refused.d)).resolveSchema('u')).toBe(false);
        const late = deps({ wait: async () => Promise.reject(new Error('The operation was aborted due to timeout')) });
        await expect((await bootAgent(keria, late.d)).resolveSchema('u')).rejects.toMatchObject({ message: expect.stringMatching(/resolved a schema: The operation was aborted/) });
        const thrown = deps({ resolve: async () => Promise.reject(new Error('HTTP POST /oobis - 500')) });
        await expect((await bootAgent(keria, thrown.d)).resolveSchema('u')).rejects.toMatchObject({ message: expect.stringMatching(/^e\.env\.dependency\.keria\.t: /) });
    });

    it('settles once KERIA holds the marker\'s key state', async () => {
        const { d, seen } = deps({ states: [async () => [], async () => ({}), async () => [{ i: 'E' }]] });
        const agent = await bootAgent(keria, d);
        expect(await agent.settle()).toBe(true);
        expect(Buffer.from(seen[0].body as Buffer).toString('latin1')).toMatch(/"t":"icp"/);
    });

    it('gives up settling at the deadline', async () => {
        const states = Array.from({ length: WAIT }, () => async () => []);
        const agent = await bootAgent(keria, deps({ states }).d);
        expect(await agent.settle()).toBe(false);
    });

    it('fails a settle when the key state cannot be read', async () => {
        const agent = await bootAgent(keria, deps({ states: [async () => Promise.reject(new Error('gone'))] }).d);
        await expect(agent.settle()).rejects.toMatchObject({ message: expect.stringMatching(/read a key state: gone/) });
    });

    it('reads a saved credential, none for a 404, and fails otherwise', async () => {
        expect(await (await bootAgent(keria, deps({}).d)).credential('E')).toEqual({ sad: { d: 'E' } });
        const missing = deps({ credential: async () => Promise.reject(new Error('HTTP GET /credentials/E - 404 Not Found - x')) });
        expect(await (await bootAgent(keria, missing.d)).credential('E')).toBeUndefined();
        const broken = deps({ credential: async () => Promise.reject(new Error('HTTP GET /credentials/E - 500 Error - x')) });
        await expect((await bootAgent(keria, broken.d)).credential('E')).rejects.toMatchObject({ message: expect.stringMatching(/read a credential/) });
    });
});
