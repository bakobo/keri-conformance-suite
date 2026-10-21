// Every kind of response the adapter writes is checked against the suite's message schema.
import { readFileSync } from 'node:fs';

import { Ajv2020 } from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';

import { handleLine } from '../src/protocol.ts';
import { acdcHex, fakeDeps } from './fakes.ts';

const schema = JSON.parse(readFileSync(new URL('../../../schema/adapter-protocol.schema.json', import.meta.url), 'utf8'));
const ajv = new Ajv2020({ strict: false });
ajv.addSchema(schema);
const validate = ajv.getSchema(`${schema.$id}#/$defs/response`)!;

const acdc = acdcHex('EPresented');
const verify = (id: number) => ({ id, op: 'acdc.verify', kels: [], registry: [], acdcs: [], schemas: [], presented: { stream: acdc } });

const requests: [string, string, Parameters<typeof fakeDeps>[0]][] = [
    ['hello', JSON.stringify({ id: 0, op: 'hello', protocol: 1, supported: [1] }), {}],
    ['refused hello', JSON.stringify({ id: 1, op: 'hello', supported: [2] }), {}],
    ['valid verdict', JSON.stringify(verify(2)), { credential: { status: { ri: 'E', s: '0', d: 'E', et: 'iss' } } }],
    ['invalid verdict', JSON.stringify(verify(3)), {}],
    ['malformed verify', JSON.stringify({ id: 4, op: 'acdc.verify' }), {}],
    ['KERIA failure', JSON.stringify({ id: 5, op: 'hello', supported: [1] }), { startFails: true }],
    ['undeclared op', JSON.stringify({ id: 6, op: 'keri.process' }), {}],
    ['unknown op', JSON.stringify({ id: 7, op: 'nope' }), {}],
    ['unreadable line', 'nope', {}],
];

describe('responses match schema/adapter-protocol.schema.json', () => {
    it.each(requests)('%s', async (_name, line, options) => {
        const response = JSON.parse(await handleLine(line, fakeDeps(options)));
        const ok = validate(response);
        expect(validate.errors ?? []).toEqual([]);
        expect(ok).toBe(true);
    });
});
