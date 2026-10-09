import { Readable } from 'node:stream';

import { beforeAll, describe, expect, it, vi } from 'vitest';
import { ready } from 'signify-ts';

import { DEFAULT_DEPS, FEATURES, OPERATIONS, PROTOCOL, handleLine, serve } from '../src/protocol.ts';
import { bytes, sigA, v1Body } from './vectors.ts';

beforeAll(async () => {
    await ready();
});

const ask = (request: unknown, deps = DEFAULT_DEPS) => JSON.parse(handleLine(JSON.stringify(request), deps));
const raw = (line: string) => JSON.parse(handleLine(line));

describe('hello', () => {
    it('negotiates version 1 from the supported list and says what it is', () => {
        const response = ask({ id: 0, op: 'hello', protocol: 2, supported: [1, 2] });
        expect(response.id).toBe(0);
        expect(response.result.protocol).toBe(PROTOCOL);
        expect(response.result.adapter.name).toBe('kcs-adapter-signify-ts');
        expect(response.result.adapter.version).toMatch(/^\d+\.\d+\.\d+/);
        expect(response.result.implementation.name).toBe('signify-ts');
        expect(response.result.implementation.commit).toMatch(/^[0-9a-f]{40}$/);
        expect(response.result.operations).toEqual([...OPERATIONS]);
        expect(response.result.features).toEqual([...FEATURES]);
        expect(response.result.composes).toEqual([]);
    });

    it('falls back to protocol when supported is absent', () => {
        expect(ask({ id: 1, op: 'hello', protocol: 1 }).result.protocol).toBe(1);
    });

    it('refuses when version 1 is not offered', () => {
        const response = ask({ id: 2, op: 'hello', protocol: 2, supported: [2] });
        expect(response.error.kind).toBe('unsupported');
        expect(response.error.message).toMatch(/^e\.feature\.unsupported\.protocol-version\.f: /);
    });

    it('does not take true for version 1', () => {
        expect(ask({ id: 3, op: 'hello', supported: [true] }).error.kind).toBe('unsupported');
    });

    it('answers a hello whose implementation cannot be identified with a harness error', () => {
        const implementation = () => {
            throw new Error('lockfile gone');
        };
        const response = ask({ id: 4, op: 'hello', supported: [1] }, { ...DEFAULT_DEPS, implementation });
        expect(response.error.kind).toBe('harness');
        expect(response.error.message).toMatch(/lockfile gone/);
    });
});

describe('requests', () => {
    it('answers cesr.parse and ignores fields it does not know', () => {
        const body = v1Body();
        const stream = Buffer.from(bytes(body, '-AAB', sigA(0))).toString('hex');
        const response = ask({ id: 5, op: 'cesr.parse', stream, extra: 'ignored' });
        expect(response.id).toBe(5);
        expect(response.result.items).toHaveLength(3);
    });

    it('answers a rejection as a result, not an error', () => {
        vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
        const response = ask({ id: 6, op: 'cesr.parse', stream: '00' });
        vi.restoreAllMocks();
        expect(response.result).toEqual({ reject: { class: 'no-version-string' } });
    });

    it('answers cesr.encode', () => {
        const response = ask({ id: 7, op: 'cesr.encode', code: 'E', raw: '00'.repeat(32), domain: 'text' });
        expect(Buffer.from(response.result.encoded, 'hex').toString('latin1')).toBe('E' + 'A'.repeat(43));
    });

    it.each([
        [{ op: 'cesr.parse' }, 'stream'],
        [{ op: 'cesr.parse', stream: 'ABCD' }, 'stream'],
        [{ op: 'cesr.parse', stream: 'abc' }, 'stream'],
        [{ op: 'cesr.encode', raw: '00', domain: 'text' }, 'code'],
        [{ op: 'cesr.encode', code: '', raw: '00', domain: 'text' }, 'code'],
        [{ op: 'cesr.encode', code: 'E', raw: '00', domain: 'qb64' }, 'domain'],
        [{ op: 'cesr.encode', code: 'E', domain: 'text' }, 'raw'],
    ])('answers a malformed field with a harness error: %j', (fields, name) => {
        const response = ask({ id: 8, ...fields });
        expect(response.id).toBe(8);
        expect(response.error.kind).toBe('harness');
        expect(response.error.message).toMatch(/^e\.input\.format\.request\.f: /);
        expect(response.error.message).toContain(`"${name}"`);
    });

    it.each(['keri.process', 'keri.emit', 'acdc.verify', 'exn.verify'])(
        'answers %s, which it does not declare, as unsupported',
        (op) => {
            const response = ask({ id: 9, op });
            expect(response.error.kind).toBe('unsupported');
            expect(response.error.message).toMatch(/^e\.feature\.unsupported\.undeclared-op\.f: /);
        },
    );

    it('answers an unknown operation with a harness error', () => {
        const response = ask({ id: 10, op: 'cesr.dance' });
        expect(response.error.kind).toBe('harness');
        expect(response.error.message).toMatch(/^e\.input\.range\.unknown-op\.f: /);
    });

    it('answers a request with no string op', () => {
        expect(ask({ id: 11 }).error.message).toMatch(/^e\.input\.format\.request\.f: .*"op"/);
    });

    it('turns an unexpected exception into a harness error', () => {
        const parseStream = () => {
            throw new TypeError('boom');
        };
        const response = ask({ id: 12, op: 'cesr.parse', stream: '' }, { ...DEFAULT_DEPS, parseStream });
        expect(response.error.kind).toBe('harness');
        expect(response.error.message).toMatch(/^e\.self\.unknown\.exception\.f: .*boom/);
    });

    it('describes a non-Error throw too', () => {
        const parseStream = () => {
            throw 42;
        };
        const response = ask({ id: 13, op: 'cesr.parse', stream: '' }, { ...DEFAULT_DEPS, parseStream });
        expect(response.error.message).toMatch(/42/);
    });
});

describe('unreadable requests', () => {
    it.each([
        ['not json', 'not JSON'],
        ['[1, 2]', 'array'],
        ['{"op": "hello"}', 'no id'],
        ['{"id": -1, "op": "hello"}', 'negative id'],
        ['{"id": 1.5, "op": "hello"}', 'fractional id'],
        ['{"id": "7", "op": "hello"}', 'string id'],
        ['', 'blank line'],
        ['{"id": 9007199254740993, "op": "hello"}', 'id too large to echo exactly'],
    ])('answers %s with an error whose id is null (%s)', (line) => {
        const response = raw(line);
        expect(response.id).toBeNull();
        expect(response.error.kind).toBe('harness');
        expect(response.error.message).toMatch(/^e\.input\.format\.request\.f: /);
    });
});

describe('serve', () => {
    async function run(chunks: (string | Buffer)[], maxLine?: number): Promise<unknown[]> {
        const out: string[] = [];
        await serve(Readable.from(chunks), (s) => void out.push(s), maxLine);
        return out.join('').split('\n').filter((l) => l !== '').map((l) => JSON.parse(l));
    }

    it('answers one line per request, across chunk boundaries, until end of input', async () => {
        const responses = await run(['{"id":1,"op":"hel', 'lo","supported":[1]}\n{"id":2,', '"op":"cesr.parse","stream":""}\n']);
        expect(responses).toHaveLength(2);
        expect((responses[0] as { id: number }).id).toBe(1);
        expect(responses[1]).toEqual({ id: 2, result: { items: [] } });
    });

    it('reads byte chunks as well as strings', async () => {
        expect(await run([Buffer.from('{"id":6,"op":"cesr.parse","stream":""}\n')])).toEqual([{ id: 6, result: { items: [] } }]);
    });

    it('answers a final line that has no newline', async () => {
        expect(await run(['{"id":3,"op":"cesr.parse","stream":""}'])).toEqual([{ id: 3, result: { items: [] } }]);
    });

    it('answers nothing for empty input', async () => {
        expect(await run([])).toEqual([]);
    });

    it('answers an oversize line with a null-id error and then the next request', async () => {
        const long = '{"id":4,"op":"cesr.parse","stream":"' + '00'.repeat(40) + '"}';
        const responses = await run([long.slice(0, 30), long.slice(30, 60), long.slice(60) + '\n', '{"id":5,"op":"cesr.parse","stream":""}\n'], 40);
        expect(responses).toHaveLength(2);
        expect(responses[0]).toMatchObject({ id: null, error: { kind: 'harness' } });
        expect((responses[0] as { error: { message: string } }).error.message).toMatch(/^e\.input\.range\.request-size\.f: /);
        expect(responses[1]).toEqual({ id: 5, result: { items: [] } });
    });

    it('answers an oversize final line that has no newline', async () => {
        const responses = await run(['x'.repeat(40)], 32);
        expect(responses).toMatchObject([{ id: null, error: { kind: 'harness' } }]);
    });

    it('answers a line that is not UTF-8 with a null-id error, never a result', async () => {
        const line = Buffer.concat([Buffer.from('{"id":7,"op":"cesr.parse","stream":"","x":"'), Buffer.from([0xff]), Buffer.from('"}\n')]);
        const responses = await run([line]);
        expect(responses).toMatchObject([{ id: null, error: { kind: 'harness' } }]);
        expect((responses[0] as { error: { message: string } }).error.message).toMatch(/^e\.input\.format\.request\.f: .*UTF-8/);
    });

    it('answers a blank line with a null-id error', async () => {
        expect(await run(['\n'])).toMatchObject([{ id: null, error: { kind: 'harness' } }]);
    });
});
