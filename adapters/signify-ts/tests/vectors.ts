// Hand-built streams for the adapter's own tests. Primitives come from signify-ts's classes;
// nothing here is read from the suite's cases, whose expected values an adapter never sees.
import { Indexer, Matter, intToB64 } from 'signify-ts';

const ascii = (s: string): Uint8Array => new TextEncoder().encode(s);
export const bytes = (...parts: string[]): Uint8Array => ascii(parts.join(''));
export const hex = (s: string): string => Buffer.from(s, 'latin1').toString('hex');
export const zeros = (n: number): string => '00'.repeat(n);

/** A KERI 1.x JSON body with its version string's size filled in. */
export function v1Body(fields: Record<string, string> = {}): string {
    const draft = (size: string) =>
        JSON.stringify({ v: `KERI10JSON${size}_`, t: 'ixn', d: 'x', i: 'y', s: '0', ...fields });
    const size = draft('000000').length;
    return draft(size.toString(16).padStart(6, '0'));
}

/** A KERI 2.x JSON body (CESR genus version 2.00) with its size filled in. */
export function v2Body(): string {
    const draft = (size: string) =>
        JSON.stringify({ v: `KERICAACAAJSON${size}.`, t: 'ixn', d: 'x', i: 'y', s: '0' });
    const size = draft('AAAA').length;
    return draft(intToB64(size, 4));
}

/** An Ed25519 indexed signature (code A), 88 characters. */
export function sigA(index = 0): string {
    return new Indexer({ raw: new Uint8Array(64), code: 'A', index }).qb64;
}

/** A big Ed25519 indexed signature with distinct index and ondex (code 2A), 92 characters. */
export function sig2A(index: number, ondex: number): string {
    return new Indexer({ raw: new Uint8Array(64), code: '2A', index, ondex }).qb64;
}

/** A big current-only Ed25519 indexed signature (code 2B), whose ondex field must be zero. */
export function sig2B(index: number): string {
    return new Indexer({ raw: new Uint8Array(64), code: '2B', index }).qb64;
}

/** A Blake3-256 digest primitive (code E), 44 characters. */
export function digestE(): string {
    return new Matter({ raw: new Uint8Array(32), code: 'E' }).qb64;
}
