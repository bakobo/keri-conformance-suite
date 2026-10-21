import { describe, expect, it } from 'vitest';

import type { Agent } from '../src/agent.ts';
import { REASONS, type Backend, holdsBody, presentedSaid, verify } from '../src/verify.ts';

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

/** By default KERIA's export carries the last stream delivered (the presented one) unchanged, after a KEL message. */
function backend(options: { credential?: Record<string, unknown>; settles?: boolean[]; resolves?: boolean; exported?: string } = {}) {
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
        async exported() {
            if (options.credential === undefined) return undefined;
            const last = Buffer.from(log.delivered.at(-1) ?? '', 'hex').toString('utf8');
            return 'exported' in options ? options.exported : `{"v":"KERI10JSON000010_"}-AAB${last}`;
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
/** The presented ACDC's body as KERIA returns it in a saved credential's sad. */
const presentedSad = () => {
    const text = Buffer.from(request().presented.stream, 'hex').toString('utf8');
    return JSON.parse(text.slice(0, text.lastIndexOf('}') + 1));
};
const saved = (extra: Record<string, unknown> = {}) => ({ sad: presentedSad(), status, ...extra });

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

describe('holdsBody', () => {
    const body = Buffer.from(acdc1('EPresented'), 'hex').toString('utf8');
    it('finds the body as a whole message, byte for byte', () => {
        expect(holdsBody(`{"v":"KERI10JSON000010_"}-AAB${body}-IAB`, body)).toBe(true);
        expect(holdsBody(`{"v":"KERI10JSON000010_"}${body}`, body)).toBe(true);
        expect(holdsBody(body, body)).toBe(true);
    });

    it('counts the version string\'s size in bytes, so a non-ASCII body is found', () => {
        const draft = (size: number) => JSON.stringify({ v: `ACDC10JSON${size.toString(16).padStart(6, '0')}_`, d: 'E', n: 'é' });
        const accented = draft(Buffer.byteLength(draft(0)));
        expect(holdsBody(`${accented}-IABEFyF`, accented)).toBe(true);
    });
    it.each([
        ['nothing', ''],
        ['the same content in another key order', Buffer.from(acdc1('EPresented', {}, ''), 'hex').toString('utf8').replace('"v"', '"v" ')],
        ['the body inside a longer message', `${body.slice(0, -1)},"x":1}`],
        ['a version string it cannot read', '{"v":"ACDC10JSONzzzzzz_"}'],
        ['a copy nested inside another message', `{"v":"KERI10JSON000010_","a":[${body}]}`],
        ['a copy after a space', ` ${body}`],
    ])('does not find it in %s', (_name, cesr) => {
        expect(holdsBody(cesr, body)).toBe(false);
    });
});

describe('verify', () => {
    it('is valid when KERIA exports the presented body unchanged, integer-like keys and all', async () => {
        const stream = acdc1('EPresented', { a: { 2: 'x', b: 'y' } }, '-IAB');
        const text = Buffer.from(stream, 'hex').toString('utf8');
        const sad = JSON.parse(text.slice(0, text.lastIndexOf('}') + 1));
        const { b } = backend({ credential: { sad, status } });
        expect(((await verify(request({ presented: { stream } }), b)) as { verdict: string }).verdict).toBe('valid');
    });

    it('is valid when KERIA saved the credential, and reports its registry', async () => {
        const { b, log } = backend({ credential: saved() });
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

    it.each([['iss', 'issued'], ['bis', 'issued'], ['brv', 'revoked']])('reports %s as %s', async (et, ts) => {
        const { b } = backend({ credential: saved({ status: { ...status, s: 'a', et } }) });
        const result = (await verify(request(), b)) as { registry: unknown };
        expect(result.registry).toEqual({ rd: 'ERegistry', n: 10, d: 'EEvent', td: 'EPresented', ts });
    });

    it.each([
        ['a second ACDC', acdc1('EPresented', {}, '') + acdc1('EOther')],
        ['bytes that are not text-domain attachments', acdc1('EPresented', {}, '-IAB\n')],
    ])('is invalid, delivering nothing, when the presented stream carries %s after its body', async (_name, stream) => {
        const { b, log } = backend({ credential: { status } });
        expect(((await verify(request({ presented: { stream } }), b)) as { reason: string }).reason).toBe(REASONS.unreadable);
        expect(log.delivered).toEqual([]);
    });

    it.each([
        ['no status', undefined],
        ['a status that is not an object', 'iss'],
        ['a sequence number that is not hex', { ...status, s: 'x' }],
        ['a missing field', { ri: 'E', s: '0', d: 'E' }],
        ['a missing registry', { s: '0', d: 'E', et: 'iss' }],
        ['a missing event SAID', { ri: 'E', s: '0', et: 'iss' }],
        ['an event type that is neither an issuance nor a revocation', { ...status, et: 'vcp' }],
        ['an event type named like an object property', { ...status, et: 'toString' }],
        ['a sequence number past 2^53', { ...status, s: '20000000000000' }],
    ])('reports no registry for %s', async (_name, value) => {
        const { b } = backend({ credential: saved({ status: value }) });
        expect(((await verify(request(), b)) as { registry: unknown }).registry).toBeNull();
    });

    it('is invalid when KERIA saved nothing, though everything settled', async () => {
        const { b } = backend({ resolves: false });
        expect(await verify(request(), b)).toEqual({ verdict: 'invalid', reason: REASONS.invalid, registry: null, edges: [] });
    });

    it('is invalid when KERIA stalled, even if it saved the credential from the front of the stream', async () => {
        const { b } = backend({ credential: { status }, settles: [true, true, true, false] });
        const result = (await verify(request(), b)) as { verdict: string; reason: string };
        expect(result).toMatchObject({ verdict: 'invalid', reason: REASONS.stalled });
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
        const { b } = backend({ credential: saved() });
        const result = (await verify(request({ expect_schema: 'EOther' }), b)) as { verdict: string; reason: string; registry: unknown };
        expect(result.verdict).toBe('invalid');
        expect(result.reason).toBe(REASONS.expected);
        expect(result.registry).not.toBeNull();
    });

    it('is invalid when KERIA holds another credential under the presented d, and reports no registry', async () => {
        const other = Buffer.from(acdc1('EPresented', { a: 'EAnother' }), 'hex').toString('utf8');
        for (const exported of [other, '', undefined]) {
            const { b } = backend({ credential: saved(), exported });
            expect(await verify(request(), b)).toEqual({ verdict: 'invalid', reason: REASONS.other, registry: null, edges: [] });
        }
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
