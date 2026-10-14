// Every kind of response the adapter writes is checked against the suite's message schema.
import { readFileSync } from 'node:fs';

import { Ajv2020 } from 'ajv/dist/2020.js';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { ready } from 'signify-ts';

import { handleLine } from '../src/protocol.ts';
import { bytes, sig2A, sigA, v1Body, v2Body } from './vectors.ts';

const schema = JSON.parse(readFileSync(new URL('../../../schema/adapter-protocol.schema.json', import.meta.url), 'utf8'));
const ajv = new Ajv2020({ strict: false });
ajv.addSchema(schema);
const validate = ajv.getSchema(`${schema.$id}#/$defs/response`)!;

beforeAll(async () => {
    await ready();
});

const hexOf = (b: Uint8Array) => Buffer.from(b).toString('hex');

const requests: [string, string][] = [
    ['hello', JSON.stringify({ id: 0, op: 'hello', protocol: 1, supported: [1] })],
    ['refused hello', JSON.stringify({ id: 1, op: 'hello', supported: [2] })],
    ['1.x items', JSON.stringify({ id: 2, op: 'cesr.parse', stream: hexOf(bytes(v1Body(), '-AAB', sig2A(1, 2))) })],
    ['2.x items', JSON.stringify({ id: 3, op: 'cesr.parse', stream: hexOf(bytes(v2Body(), '-_AAACAA', '-KAW', sigA(0))) })],
    ['rejection', JSON.stringify({ id: 4, op: 'cesr.parse', stream: '00' })],
    ['encoding', JSON.stringify({ id: 5, op: 'cesr.encode', code: 'E', raw: '00'.repeat(32), domain: 'text' })],
    ['refused encoding', JSON.stringify({ id: 6, op: 'cesr.encode', code: 'E', raw: '00', domain: 'binary' })],
    ['undeclared op', JSON.stringify({ id: 7, op: 'keri.process' })],
    ['unknown op', JSON.stringify({ id: 8, op: 'nope' })],
    ['unreadable line', 'nope'],
];

describe('responses match schema/adapter-protocol.schema.json', () => {
    it.each(requests)('%s', (_name, line) => {
        vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
        const response = JSON.parse(handleLine(line));
        vi.restoreAllMocks();
        const ok = validate(response);
        expect(validate.errors ?? []).toEqual([]);
        expect(ok).toBe(true);
    });
});
