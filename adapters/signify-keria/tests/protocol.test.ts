import { Readable } from 'node:stream';

import { describe, expect, it } from 'vitest';

import { FEATURES, OPERATIONS, PROTOCOL, type Deps, handleLine, serve, session } from '../src/protocol.ts';
import { KERIA, acdcHex, fakeDeps } from './fakes.ts';

const ask = async (request: unknown, deps: Deps = fakeDeps()) => JSON.parse(await handleLine(JSON.stringify(request), deps));
const raw = async (line: string) => JSON.parse(await handleLine(line, fakeDeps()));
const verifyRequest = (id: number) => ({ id, op: 'acdc.verify', kels: [], registry: [], acdcs: [], schemas: [], presented: { stream: acdcHex('EPresented') } });

describe('hello', () => {
    it('negotiates version 1 from the supported list and says what it is', async () => {
        const response = await ask({ id: 0, op: 'hello', protocol: 2, supported: [1, 2] });
        expect(response.id).toBe(0);
        expect(response.result.protocol).toBe(PROTOCOL);
        expect(response.result.adapter.name).toBe('kcs-adapter-signify-keria');
        expect(response.result.adapter.version).toMatch(/^\d+\.\d+\.\d+/);
        expect(response.result.implementation.name).toBe('signify-ts-keria');
        expect(response.result.implementation.version).toMatch(/ with KERIA 0\.4\.1 \(keripy 1\.2\.14\)$/);
        expect(response.result.operations).toEqual([...OPERATIONS]);
        expect(response.result.features).toEqual([...FEATURES]);
        expect(response.result.composes).toEqual([]);
    });

    it('falls back to protocol when supported is absent', async () => {
        expect((await ask({ id: 1, op: 'hello', protocol: 1 })).result.protocol).toBe(1);
    });

    it('refuses when version 1 is not offered, and does not take true for 1', async () => {
        const response = await ask({ id: 2, op: 'hello', protocol: 2, supported: [2] });
        expect(response.error.kind).toBe('unsupported');
        expect(response.error.message).toMatch(/^e\.feature\.unsupported\.protocol-version\.f: /);
        expect((await ask({ id: 3, op: 'hello', supported: [true] })).error.kind).toBe('unsupported');
    });

    it('answers with KERIA\'s own failure when KERIA cannot start', async () => {
        const response = await ask({ id: 4, op: 'hello', supported: [1] }, fakeDeps({ startFails: true }));
        expect(response.error.kind).toBe('harness');
        expect(response.error.message).toMatch(/^e\.env\.dependency\.keria-start\.t: /);
    });

    it('starts KERIA once per session and tells the caller', async () => {
        const starts = { count: 0 };
        const seen: string[] = [];
        const deps = fakeDeps({ starts }, (keria) => seen.push(keria.container));
        await ask({ id: 5, op: 'hello', supported: [1] }, deps);
        await ask(verifyRequest(6), deps);
        expect(starts.count).toBe(1);
        expect(seen).toEqual(['cid']);
    });
});

describe('requests', () => {
    it('answers acdc.verify with a verdict, offering the agent the request\'s schemas', async () => {
        const served: Map<string, string>[] = [];
        const schema = Buffer.from(JSON.stringify({ $id: 'ESchema' })).toString('hex');
        const response = await ask({ ...verifyRequest(7), schemas: [schema] }, fakeDeps({ served }));
        expect(response.result.verdict).toBe('invalid');
        expect(served).toEqual([new Map([['ESchema', schema]])]);
    });

    it('gives KERIA the URL it reaches the schema server at inside its container', async () => {
        const backend = fakeDeps().backend(KERIA);
        expect(await backend.serveSchemas(new Map([['ESchema', '7b7d']]))).toEqual(new Map([['ESchema', 'http://127.0.0.1:7700/oobi/ESchema']]));
    });

    it('answers a malformed verify with a harness error', async () => {
        const response = await ask({ id: 8, op: 'acdc.verify' });
        expect(response.error).toMatchObject({ kind: 'harness', message: expect.stringMatching(/^e\.input\.format\.request\.f: /) });
    });

    it('answers an undeclared operation as unsupported and an unknown one as a harness error', async () => {
        expect((await ask({ id: 9, op: 'acdc.present' })).error.message).toMatch(/^e\.feature\.unsupported\.undeclared-op\.f: /);
        expect((await ask({ id: 10, op: 'nope' })).error).toMatchObject({ kind: 'harness', message: expect.stringMatching(/^e\.input\.range\.unknown-op\.f: /) });
    });

    it("issues through the session's KERIA, and answers a malformed issue with a harness error", async () => {
        const schema = Buffer.from(JSON.stringify({ $id: 'ESchema' })).toString('hex');
        const credentials = [{ name: 'c', issuer: 'I', issuee: 'H', schema: 'ESchema', attributes: { name: 'Zoe' }, registry: 'ptel-1x' }];
        const response = await ask({ id: 14, op: 'acdc.issue', roles: ['I', 'H'], schemas: [schema], credentials });
        expect(Object.keys(response.result.kels)).toEqual(['I', 'H']);
        expect(Object.keys(response.result.credentials)).toEqual(['c']);
        expect((await ask({ id: 15, op: 'acdc.issue', roles: [], schemas: [], credentials: [] })).error.kind).toBe('harness');
    });

    it('answers a request with no string op', async () => {
        expect((await ask({ id: 11 })).error.message).toMatch(/no string "op"/);
    });

    it('turns an unexpected exception, Error or not, into a harness error', async () => {
        const deps: Deps = { ...fakeDeps(), keria: () => Promise.reject(new Error('boom')) };
        expect((await ask({ id: 12, op: 'hello', supported: [1] }, deps)).error.message).toMatch(/^e\.self\.unknown\.exception\.f: .*boom/);
        const odd: Deps = { ...fakeDeps(), keria: () => Promise.reject('odd') };
        expect((await ask({ id: 13, op: 'hello', supported: [1] }, odd)).error.message).toMatch(/odd$/);
    });
});

describe('the default session', () => {
    it('uses the real parts, which fail cleanly with no KERIA there', async () => {
        const backend = session().backend(KERIA);
        await expect(backend.serveSchemas(new Map())).rejects.toMatchObject({ message: expect.stringMatching(/^e\.env\.dependency\.keria\.t: /) });
        await expect(backend.agent()).rejects.toMatchObject({ message: expect.stringMatching(/^e\.env\.dependency\.keria\.t: /) });
    });
});

describe('unreadable requests', () => {
    it.each([['not JSON', 'nope'], ['not an object', '[1]'], ['null', 'null']])('answers %s with a null-id error', async (_name, line) => {
        expect(await raw(line)).toMatchObject({ id: null, error: { kind: 'harness' } });
    });

    it.each([['no id', {}], ['a negative id', { id: -1 }], ['a fractional id', { id: 1.5 }], ['an unsafe id', { id: 2 ** 53 }], ['a string id', { id: '1' }]])(
        'answers a request with %s with a null-id error',
        async (_name, request) => {
            expect(await raw(JSON.stringify({ ...request, op: 'hello' }))).toMatchObject({ id: null, error: { kind: 'harness' } });
        },
    );
});

describe('serve', () => {
    async function run(chunks: (string | Buffer)[], maxLine?: number): Promise<unknown[]> {
        const out: string[] = [];
        await serve(Readable.from(chunks), (s) => void out.push(s), fakeDeps(), maxLine);
        return out.join('').split('\n').filter((l) => l !== '').map((l) => JSON.parse(l));
    }

    it('answers one line per request, across chunk boundaries, until end of input', async () => {
        const responses = await run(['{"id":1,"op":"hel', 'lo","supported":[1]}\n{"id":2,', '"op":"nope"}\n']);
        expect(responses.map((r) => (r as { id: number }).id)).toEqual([1, 2]);
    });

    it('reads byte chunks, and answers a final line that has no newline', async () => {
        expect(await run([Buffer.from('{"id":6,"op":"nope"}')])).toMatchObject([{ id: 6 }]);
    });

    it('answers nothing for empty input', async () => {
        expect(await run([])).toEqual([]);
    });

    it('answers an oversize line with a null-id error and then the next request', async () => {
        const long = '{"id":4,"op":"nope","x":"' + '0'.repeat(40) + '"}';
        const responses = await run([long.slice(0, 30), long.slice(30, 60), long.slice(60) + '\n', '{"id":5,"op":"nope"}\n'], 40);
        expect(responses).toHaveLength(2);
        expect((responses[0] as { error: { message: string } }).error.message).toMatch(/^e\.input\.range\.request-size\.f: /);
        expect(responses[1]).toMatchObject({ id: 5 });
    });

    it('answers an oversize final line that has no newline', async () => {
        expect(await run(['x'.repeat(40)], 32)).toMatchObject([{ id: null, error: { kind: 'harness' } }]);
    });

    it('answers a line that is not UTF-8 with a null-id error', async () => {
        const line = Buffer.concat([Buffer.from('{"id":7,"op":"nope","x":"'), Buffer.from([0xff]), Buffer.from('"}\n')]);
        const responses = await run([line]);
        expect((responses[0] as { error: { message: string } }).error.message).toMatch(/^e\.input\.format\.request\.f: .*UTF-8/);
    });

    it('answers a blank line with a null-id error', async () => {
        expect(await run(['\n'])).toMatchObject([{ id: null, error: { kind: 'harness' } }]);
    });
});
