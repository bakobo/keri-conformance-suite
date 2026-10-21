import { describe, expect, it } from 'vitest';

import type { Agent } from '../src/agent.ts';
import { REASONS, type Backend, presentedSaid, verify } from '../src/verify.ts';

/** An ACDC 1.x body with a correct version string, and whatever follows it. */
function acdc1(d: string, extra: Record<string, unknown> = {}, after = ''): string {
    const draft = (size: number) => JSON.stringify({ v: `ACDC10JSON${size.toString(16).padStart(6, '0')}_`, d, ...extra });
    const body = draft(draft(0).length);
    return Buffer.from(body + after).toString('hex');
}

interface Log {
    delivered: string[];
    resolved: string[];
    served: Map<string, string>[];
}

function backend(options: { credential?: Record<string, unknown>; settles?: boolean[]; resolves?: boolean } = {}) {
    const log: Log = { delivered: [], resolved: [], served: [] };
    const settles = [...(options.settles ?? [])];
    const agent: Agent = {
        async resolveSchema(url) {
            log.resolved.push(url);
            return options.resolves ?? true;
        },
        async deliver(bytes) {
            log.delivered.push(Buffer.from(bytes).toString('hex'));
        },
        async settle() {
            return settles.length > 0 ? (settles.shift() as boolean) : true;
        },
        async credential() {
            return options.credential;
        },
    };
    const b: Backend = {
        agent: async () => agent,
        async serveSchemas(schemas) {
            log.served.push(schemas);
            return new Map([...schemas.keys()].map((said) => [said, `http://127.0.0.1:7700/oobi/${said}`]));
        },
    };
    return { b, log };
}

const SCHEMA = Buffer.from(JSON.stringify({ $id: 'ESchema', type: 'object' })).toString('hex');
const request = (overrides: Record<string, unknown> = {}) => ({
    kels: [{ stream: 'aa' }],
    registry: [{ stream: 'bb' }],
    acdcs: [{ stream: acdc1('EFar') }],
    schemas: [SCHEMA],
    presented: { stream: acdc1('EPresented', { s: 'ESchema' }, '-IAB') },
    ...overrides,
});

const status = { ri: 'ERegistry', s: '1', d: 'EEvent', et: 'rev' };

describe('presentedSaid', () => {
    it('reads d through the 1.x version string', () => {
        expect(presentedSaid(Buffer.from(acdc1('EOne', {}, '-IAB'), 'hex'))).toBe('EOne');
    });

    it.each([
        ['no 1.x version string', Buffer.from('{"v":"ACDC20JSON"}')],
        ['a size past the end', Buffer.from('{"v":"ACDC10JSON0000ff_","d":"E"}')],
        ['a body that is not JSON at its size', Buffer.from('{"v":"ACDC10JSON000018_","d":"E"}')],
        ['a d that is not a string', Buffer.from(acdc1(1 as unknown as string), 'hex')],
    ])('reads nothing from %s', (_name, stream) => {
        expect(presentedSaid(stream)).toBeUndefined();
    });
});

describe('verify', () => {
    it('is valid when KERIA saved the credential, and reports its registry', async () => {
        const { b, log } = backend({ credential: { sad: { s: 'ESchema' }, status } });
        const result = await verify(request({ expect_schema: 'ESchema' }), b);
        expect(result).toEqual({
            verdict: 'valid',
            reason: REASONS.valid,
            registry: { rd: 'ERegistry', n: 1, d: 'EEvent', td: 'EPresented', ts: 'revoked' },
            edges: [],
        });
        expect(log.served).toEqual([new Map([['ESchema', SCHEMA]])]);
        expect(log.resolved).toEqual(['http://127.0.0.1:7700/oobi/ESchema']);
        expect(log.delivered).toEqual(['aa', 'bb', request().acdcs[0].stream, request().presented.stream]);
    });

    it('reports an issued registry state', async () => {
        const { b } = backend({ credential: { status: { ...status, s: 'a', et: 'iss' } } });
        const result = (await verify(request(), b)) as { registry: unknown };
        expect(result.registry).toEqual({ rd: 'ERegistry', n: 10, d: 'EEvent', td: 'EPresented', ts: 'issued' });
    });

    it.each([
        ['no status', undefined],
        ['a status that is not an object', 'iss'],
        ['a sequence number that is not hex', { ...status, s: 'x' }],
        ['a missing field', { ri: 'E', s: '0', d: 'E' }],
        ['a missing registry', { s: '0', d: 'E', et: 'iss' }],
        ['a missing event SAID', { ri: 'E', s: '0', et: 'iss' }],
    ])('reports no registry for %s', async (_name, value) => {
        const { b } = backend({ credential: { status: value } });
        expect(((await verify(request(), b)) as { registry: unknown }).registry).toBeNull();
    });

    it('is invalid when KERIA saved nothing, though everything settled', async () => {
        const { b } = backend({ resolves: false });
        expect(await verify(request(), b)).toEqual({ verdict: 'invalid', reason: REASONS.invalid, registry: null, edges: [] });
    });

    it('stops waiting once KERIA stalls, and says so', async () => {
        const { b, log } = backend({ settles: [true, false] });
        const result = (await verify(request(), b)) as { reason: string };
        expect(result.reason).toBe(REASONS.stalled);
        expect(log.delivered).toHaveLength(4);
    });

    it('is stalled when only the final settle fails', async () => {
        const { b } = backend({ settles: [true, true, true, true, false] });
        expect(((await verify(request(), b)) as { reason: string }).reason).toBe(REASONS.stalled);
    });

    it('is invalid when the credential has a schema other than the one expected', async () => {
        const { b } = backend({ credential: { sad: { s: 'EOther' }, status } });
        const result = (await verify(request({ expect_schema: 'ESchema' }), b)) as { verdict: string; reason: string; registry: unknown };
        expect(result.verdict).toBe('invalid');
        expect(result.reason).toBe(REASONS.expected);
        expect(result.registry).not.toBeNull();
    });

    it('is invalid when there is no sad to compare with the expected schema', async () => {
        const { b } = backend({ credential: { status } });
        expect(((await verify(request({ expect_schema: 'ESchema' }), b)) as { verdict: string }).verdict).toBe('invalid');
    });

    it('is invalid, delivering nothing, when the presented stream cannot be read', async () => {
        const { b, log } = backend({ credential: { status } });
        expect(await verify(request({ presented: { stream: 'ff' } }), b)).toEqual({
            verdict: 'invalid',
            reason: REASONS.unreadable,
            registry: null,
            edges: [],
        });
        expect(log.delivered).toEqual([]);
    });

    it('does not deliver a far node that carries the presented credential\'s SAID', async () => {
        const { b, log } = backend();
        await verify(request({ acdcs: [{ stream: acdc1('EPresented') }, { stream: 'cc' }] }), b);
        expect(log.delivered).toEqual(['aa', 'bb', 'cc', request().presented.stream]);
    });

    it.each([
        ['kels that are not a list', { kels: {} }, /"kels" must be a list/],
        ['a registry entry that is not an object', { registry: [null] }, /Each entry of "registry"/],
        ['an ACDC stream that is not hex', { acdcs: [{ stream: 'zz' }] }, /"acdcs" must hold lowercase hex/],
        ['an upper-case stream', { kels: [{ stream: 'AA' }] }, /"kels" must hold lowercase hex/],
        ['no presented object', { presented: null }, /"presented" must be an object/],
        ['a presented stream that is not a string', { presented: { stream: 1 } }, /"presented" must hold/],
        ['schemas that are not a list', { schemas: 'aa' }, /"schemas" must be a list/],
        ['a schema that is not a string', { schemas: [1] }, /"schemas" must be a list/],
        ['a schema that is not hex', { schemas: ['zz'] }, /"schemas" must hold/],
        ['an empty expect_schema', { expect_schema: '' }, /"expect_schema"/],
        ['an expect_schema that is not a string', { expect_schema: 1 }, /"expect_schema"/],
    ])('refuses a request with %s', async (_name, overrides, message) => {
        const { b } = backend();
        await expect(verify(request(overrides), b)).rejects.toMatchObject({ kind: 'harness', message: expect.stringMatching(message) });
    });
});
