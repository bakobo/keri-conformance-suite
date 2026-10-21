import { describe, expect, it } from 'vitest';

import { offered, reachesOut } from '../src/schemas.ts';

const hex = (doc: unknown) => Buffer.from(typeof doc === 'string' ? doc : JSON.stringify(doc)).toString('hex');

describe('reachesOut', () => {
    it('finds nothing in a schema with no references', () => {
        expect(reachesOut({ $id: 'E1', type: 'object', properties: { a: { type: 'string' } } })).toBe(false);
    });

    it.each([
        ['a remote $ref', { $id: 'E1', properties: { a: { $ref: 'https://example.com/s.json' } } }],
        ['a $dynamicRef', { $dynamicRef: 'https://example.com/s.json' }],
        ['a $recursiveRef that is not a string', { $recursiveRef: 1 }],
        ['a local reference to nothing', { $ref: '#/$defs/missing' }],
        ['a plain-name fragment', { $ref: '#anchor' }],
        ['a nested $id', { properties: { a: { $id: 'https://example.com/a' } } }],
        ['a nested id', { allOf: [{ id: 'x' }] }],
        ['a reference whose target reaches out', { $defs: { a: { $ref: 'https://example.com' } }, $ref: '#/$defs/a' }],
        ['a pointer that is not percent-decodable', { $ref: '#/%E0%A4%A' }],
        ['an index past the end', { allOf: [{}], $ref: '#/allOf/1' }],
        ['an index too long to name anything', { allOf: [{}], $ref: '#/allOf/0000000000' }],
        ['an index into something that is not a list', { $defs: { a: {} }, $ref: '#/$defs/0' }],
    ])('finds %s', (_name, schema) => {
        expect(reachesOut(schema)).toBe(true);
    });

    it.each([
        ['the root', { $ref: '#' }],
        ['an escaped pointer', { $defs: { 'a/b~c': { type: 'string' } }, $ref: '#/$defs/a~1b~0c' }],
        ['an array index', { allOf: [{ type: 'string' }], $ref: '#/allOf/0' }],
        ['data that looks like a reference', { const: { $ref: 'https://example.com' }, enum: [{ $id: 'x' }] }],
        ['a property named like a keyword', { properties: { $ref: { type: 'string' }, $id: { type: 'string' } } }],
        ['a cycle of local references', { $defs: { a: { $ref: '#/$defs/b' }, b: { $ref: '#/$defs/a' } }, $ref: '#/$defs/a' }],
        ['a percent-encoded pointer', { $defs: { 'a b': {} }, $ref: '#/$defs/a%20b' }],
    ])('follows %s without reaching out', (_name, schema) => {
        expect(reachesOut(schema)).toBe(false);
    });
});

describe('offered', () => {
    it('keys each schema by its $id and keeps the hex it came as', () => {
        const doc = hex({ $id: 'EAbc_-1', type: 'object' });
        expect(offered([doc])).toEqual(new Map([['EAbc_-1', doc]]));
    });

    it.each([
        ['not JSON', 'nope'],
        ['not an object', [1]],
        ['no $id', { type: 'object' }],
        ['an $id that is not a string', { $id: 1 }],
        ['an $id that cannot be a path segment', { $id: 'E/../x' }],
        ['a schema that reaches out', { $id: 'E1', $ref: 'https://example.com' }],
    ])('leaves out a schema with %s', (_name, doc) => {
        expect(offered([hex(doc)]).size).toBe(0);
    });
});
