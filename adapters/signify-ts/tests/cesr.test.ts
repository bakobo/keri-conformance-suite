import { beforeAll, describe, expect, it, vi } from 'vitest';
import { ready, type ParseResult } from 'signify-ts';

import { encode, parseStream } from '../src/cesr.ts';
import { OpError } from '../src/errors.ts';
import { bytes, digestE, hex, sig2A, sig2B, sigA, v1Body, v2Body, zeros } from './vectors.ts';

beforeAll(async () => {
    await ready();
});

const message = (body: string, start = 0, version = '1.0') => ({
    kind: 'message',
    start,
    end: start + body.length,
    proto: 'KERI',
    version,
    serialization: 'JSON',
    size: body.length,
});

describe('cesr.parse', () => {
    it('answers an empty stream with no items', () => {
        expect(parseStream(new Uint8Array())).toEqual({ items: [] });
    });

    it('reports a 1.x message, its count code and its indexed signature', () => {
        const body = v1Body();
        const n = body.length;
        expect(parseStream(bytes(body, '-AAB', sigA(0)))).toEqual({
            items: [
                message(body),
                { kind: 'counter', start: n, end: n + 4, code: '-A', size: 1, group_end: n + 92 },
                { kind: 'indexed', start: n + 4, end: n + 92, code: 'A', raw: zeros(64), index: 0 },
            ],
        });
    });

    it('reports two messages in stream order', () => {
        const body = v1Body();
        const n = body.length;
        const result = parseStream(bytes(body, body));
        expect(result).toEqual({ items: [message(body), message(body, n)] });
    });

    it('reports ondex as signify-ts read it when the code has an ondex field', () => {
        const body = v1Body();
        const n = body.length;
        const result = parseStream(bytes(body, '-AAB', sig2A(1, 3)));
        expect(result).toEqual({
            items: [
                message(body),
                { kind: 'counter', start: n, end: n + 4, code: '-A', size: 1, group_end: n + 96 },
                { kind: 'indexed', start: n + 4, end: n + 96, code: '2A', raw: zeros(64), index: 1, ondex: 3 },
            ],
        });
    });

    it('reads a current-only ondex back from the encoding, as signify-ts stores none', () => {
        const body = v1Body();
        const n = body.length;
        const result = parseStream(bytes(body, '-AAB', sig2B(2)));
        expect(result).toEqual({
            items: [
                message(body),
                { kind: 'counter', start: n, end: n + 4, code: '-A', size: 1, group_end: n + 96 },
                { kind: 'indexed', start: n + 4, end: n + 96, code: '2B', raw: zeros(64), index: 2, ondex: 0 },
            ],
        });
    });

    it('reports a 1.x quadlet wrapper and the groups inside it', () => {
        const body = v1Body();
        const n = body.length;
        // -V counts quadlets: -AAB (4) + one signature (88) = 92 bytes = 23 quadlets (X).
        const result = parseStream(bytes(body, '-VAX', '-AAB', sigA(0)));
        expect(result).toEqual({
            items: [
                message(body),
                { kind: 'counter', start: n, end: n + 4, code: '-V', size: 23, group_end: n + 96 },
                { kind: 'counter', start: n + 4, end: n + 8, code: '-A', size: 1, group_end: n + 96 },
                { kind: 'indexed', start: n + 8, end: n + 96, code: 'A', raw: zeros(64), index: 0 },
            ],
        });
    });

    it('reports a 2.x message, a genus code and a 2.00 signature group', () => {
        const body = v2Body();
        const n = body.length;
        // -K counts quadlets: one 88-byte signature is 22 quadlets (W).
        const result = parseStream(bytes(body, '-_AAACAA', '-KAW', sigA(0)));
        expect(result).toEqual({
            items: [
                message(body, 0, '2.0'),
                { kind: 'genus', start: n, end: n + 8, code: '-_AAACAA', genus: 'AAA', version: '2.00' },
                { kind: 'counter', start: n + 8, end: n + 12, code: '-K', size: 22, group_end: n + 100 },
                { kind: 'indexed', start: n + 12, end: n + 100, code: 'A', raw: zeros(64), index: 0 },
            ],
        });
    });

    it('reports nested 2.00 groups and a primitive in a non-signature group', () => {
        const body = v2Body();
        const n = body.length;
        // -C wraps -J (4 + 44 = 48 bytes, 12 quadlets: M); -J holds one 44-byte digest (11: L).
        const result = parseStream(bytes(body, '-CAM', '-JAL', digestE()));
        expect(result).toEqual({
            items: [
                message(body, 0, '2.0'),
                { kind: 'counter', start: n, end: n + 4, code: '-C', size: 12, group_end: n + 52 },
                { kind: 'counter', start: n + 4, end: n + 8, code: '-J', size: 11, group_end: n + 52 },
                { kind: 'primitive', start: n + 8, end: n + 52, code: 'E', raw: zeros(32) },
            ],
        });
    });

    it('reports a 2.00 group whose code signify-ts does not know as a count code with no members', () => {
        const body = v2Body();
        const n = body.length;
        const result = parseStream(bytes(body, '-zAB', 'AAAA'));
        expect(result).toEqual({
            items: [
                message(body, 0, '2.0'),
                { kind: 'counter', start: n, end: n + 4, code: '-z', size: 1, group_end: n + 8 },
            ],
        });
    });

    it('reports a big 2.00 count code with its eight-character header', () => {
        const body = v2Body();
        const n = body.length;
        const result = parseStream(bytes(body, '--KAAAAW', sigA(0)));
        expect(result).toEqual({
            items: [
                message(body, 0, '2.0'),
                { kind: 'counter', start: n, end: n + 8, code: '--K', size: 22, group_end: n + 96 },
                { kind: 'indexed', start: n + 8, end: n + 96, code: 'A', raw: zeros(64), index: 0 },
            ],
        });
    });

    it('rejects a stream that ends inside a message, with the parser\'s own code as the class', () => {
        const body = v1Body();
        const spy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
        expect(parseStream(bytes(body.slice(0, -1)))).toEqual({ reject: { class: 'incomplete' } });
        expect(String(spy.mock.calls[0][0])).toContain('incomplete');
        spy.mockRestore();
    });

    it('rejects bytes with no version string', () => {
        const spy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
        expect(parseStream(bytes('not a stream'))).toEqual({ reject: { class: 'no-version-string' } });
        spy.mockRestore();
    });

    const fake = (result: ParseResult) => () => result;

    it('treats a parser that stops early without an error as an adapter fault', () => {
        const parser = fake({ messages: [], errors: [], consumed: 0 });
        expect(() => parseStream(bytes('abc'), parser)).toThrowError(OpError);
        expect(() => parseStream(bytes('abc'), parser)).toThrowError(/e\.self\.unknown\.unconsumed\.f/);
    });

    it('refuses a 2.00 group whose header end disagrees with where its first member starts', () => {
        const stream = bytes('-KAB', 'AAAA');
        const parser = fake({
            messages: [
                {
                    proto: 'KERI', version: '2.0', kind: 'JSON', ilk: null, sn: null, said: null, sad: null,
                    span: { start: 0, end: 0 },
                    attachments: [
                        {
                            kind: 'group', code: '-K', count: 1, genus: 2, span: { start: 0, end: 8 }, state: 'known',
                            items: [{ kind: 'primitive', code: 'A', class: 'matter', span: { start: 5, end: 8 } }],
                        },
                    ],
                },
            ],
            errors: [],
            consumed: 8,
        });
        expect(() => parseStream(stream, parser)).toThrowError(/e\.self\.unknown\.group-header\.f/);
    });

    it('refuses a 1.x group whose header end disagrees with where its first member starts', () => {
        const stream = bytes('-AAB', sigA(0));
        const parser = fake({
            messages: [
                {
                    proto: 'KERI', version: '1.0', kind: 'JSON', ilk: null, sn: null, said: null, sad: null,
                    span: { start: 0, end: 0 },
                    attachments: [
                        {
                            kind: 'group', code: '-A', count: 1, genus: 1, span: { start: 0, end: 92 }, state: 'known',
                            items: [{ kind: 'primitive', code: 'A', class: 'indexer', span: { start: 3, end: 92 } }],
                        },
                    ],
                },
            ],
            errors: [],
            consumed: 92,
        });
        expect(() => parseStream(stream, parser)).toThrowError(/e\.self\.unknown\.group-header\.f/);
    });

    it('refuses a primitive whose re-read code differs from the one the parser framed', () => {
        const stream = bytes('-JAL', digestE());
        const parser = fake({
            messages: [
                {
                    proto: 'KERI', version: '2.0', kind: 'JSON', ilk: null, sn: null, said: null, sad: null,
                    span: { start: 0, end: 0 },
                    attachments: [
                        {
                            kind: 'group', code: '-J', count: 11, genus: 2, span: { start: 0, end: 48 }, state: 'known',
                            items: [{ kind: 'primitive', code: 'F', class: 'matter', span: { start: 4, end: 48 } }],
                        },
                    ],
                },
            ],
            errors: [],
            consumed: 48,
        });
        expect(() => parseStream(stream, parser)).toThrowError(/e\.self\.unknown\.primitive-code\.f/);
    });
});

describe('cesr.encode', () => {
    it('encodes in the text domain with signify-ts\'s Matter', () => {
        expect(encode('E', new Uint8Array(32), 'text')).toEqual({ encoded: hex(digestE()) });
    });

    it('answers the binary domain as unsupported, since signify-ts has no qb2', () => {
        expect(() => encode('E', new Uint8Array(32), 'binary')).toThrowError(/e\.feature\.unsupported\.domain\.f/);
        try {
            encode('E', new Uint8Array(32), 'binary');
        } catch (err) {
            expect((err as OpError).kind).toBe('unsupported');
        }
    });

    it('answers a code signify-ts refuses as unsupported, naming its reason', () => {
        let caught: unknown;
        try {
            encode('#', new Uint8Array(1), 'text');
        } catch (err) {
            caught = err;
        }
        expect(caught).toBeInstanceOf(OpError);
        expect((caught as OpError).kind).toBe('unsupported');
        expect((caught as OpError).message).toMatch(/^e\.input\.format\.encode-refused\.f: /);
    });

    it('reports a non-Error throw from signify-ts too', () => {
        const thrower = () => {
            throw 'plain string';
        };
        expect(() => encode('E', new Uint8Array(32), 'text', thrower)).toThrowError(/plain string/);
    });
});
