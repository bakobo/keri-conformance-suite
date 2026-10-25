import { beforeAll, describe, expect, it } from 'vitest';
import { ready } from 'signify-ts';

import type { Agent } from '../src/agent.ts';
import { issue } from '../src/issue.ts';
import type { Backend } from '../src/verify.ts';

beforeAll(async () => {
    await ready();
});

interface Log {
    resolved: string[];
    issued: { name: string; data: { ri: string; s: string; a: Record<string, unknown> } }[];
    registries: string[][];
}

function backend(refuse?: string) {
    const log: Log = { resolved: [], issued: [], registries: [] };
    const unused = async (): Promise<never> => {
        throw new Error('issue does not verify');
    };
    const agent: Agent = {
        async resolveSchema(url) {
            log.resolved.push(url);
            return true;
        },
        deliver: unused,
        settle: unused,
        credential: unused,
        exported: unused,
        identify: async (name) => `E-${name}`,
        async registry(name, registryName) {
            log.registries.push([name, registryName]);
            return { regk: `EReg-${registryName}`, vcp: `{"t":"vcp","r":"${registryName}"}` };
        },
        async issue(name, data) {
            log.issued.push({ name, data });
            return refuse !== undefined ? { refused: refuse } : { acdc: `{"v":"ACDC","ri":"${data.ri}"}`, iss: '{"t":"iss"}' };
        },
        kel: async (pre) => `{"i":"${pre}"}`,
    };
    const b: Backend = {
        agent: async () => agent,
        serveSchemas: async (schemas) => new Map([...schemas.keys()].map((said) => [said, `http://s/oobi/${said}`])),
    };
    return { b, log };
}

const SCHEMA = Buffer.from(JSON.stringify({ $id: 'ESchema', type: 'object' })).toString('hex');
const hex = (text: string) => Buffer.from(text).toString('hex');
const credential = (overrides: Record<string, unknown> = {}) => ({
    name: 'c',
    issuer: 'I',
    issuee: 'H',
    schema: 'ESchema',
    attributes: { name: 'Zoe' },
    registry: 'ptel-1x',
    ...overrides,
});
const request = (overrides: Record<string, unknown> = {}) => ({ roles: ['I', 'H'], schemas: [SCHEMA], credentials: [credential()], ...overrides });

describe('issue', () => {
    it("issues each credential in a registry of its own, with signify-ts's issuee and a fresh salt", async () => {
        const { b, log } = backend();
        const result = (await issue(request({ credentials: [credential(), credential({ name: 'd', issuee: undefined })] }), b)) as {
            kels: Record<string, string>;
            credentials: Record<string, { acdc: string; registry: string }>;
        };
        expect(log.resolved).toEqual(['http://s/oobi/ESchema']);
        expect(log.registries).toEqual([
            ['role-0', 'registry-0'],
            ['role-0', 'registry-1'],
        ]);
        expect(log.issued[0].data).toMatchObject({ ri: 'EReg-registry-0', s: 'ESchema', a: { name: 'Zoe', i: 'E-role-1' } });
        expect(log.issued[0].data.a.u).toMatch(/^0A[A-Za-z0-9_-]{22}$/);
        expect(log.issued[1].data.a.u).not.toBe(log.issued[0].data.a.u);
        expect('i' in log.issued[1].data.a).toBe(false);
        expect(result.kels).toEqual({ I: hex('{"i":"E-role-0"}'), H: hex('{"i":"E-role-1"}') });
        expect(result.credentials.c).toEqual({ acdc: hex('{"v":"ACDC","ri":"EReg-registry-0"}'), registry: hex('{"t":"vcp","r":"registry-0"}{"t":"iss"}') });
    });

    it("answers KERIA's refusal with its first line", async () => {
        const { b } = backend('Credential schema validation failed for E: no\n\nschema');
        expect(await issue(request(), b)).toEqual({ refused: { reason: 'KERIA refuses the credential signify-ts built: Credential schema validation failed for E: no' } });
    });

    it.each([
        ['no roles', { roles: [] }],
        ['a repeated role', { roles: ['I', 'I'] }],
        ['an empty role', { roles: [''] }],
        ['schemas that are not hex', { schemas: ['zz'] }],
        ['schemas that are not a list', { schemas: 'aa' }],
        ['no credentials', { credentials: [] }],
        ['credentials that are not a list', { credentials: {} }],
        ['a credential that is not an object', { credentials: [null] }],
        ['an issuer the request does not create', { credentials: [credential({ issuer: 'X' })] }],
        ['an issuee the request does not create', { credentials: [credential({ issuee: 'X' })] }],
        ['attributes that are not a map', { credentials: [credential({ attributes: [] })] }],
        ['a name used twice', { credentials: [credential(), credential()] }],
    ])('answers %s with a harness error', async (_name, overrides) => {
        await expect(issue(request(overrides), backend().b)).rejects.toMatchObject({ kind: 'harness', message: expect.stringMatching(/^e\.input\.format\.request\.f: /) });
    });

    it('declines a KERI 2.0 registry and an edge section as unsupported', async () => {
        for (const asked of [credential({ registry: 'bup' }), credential({ edges: {} })]) {
            await expect(issue(request({ credentials: [asked] }), backend().b)).rejects.toMatchObject({ kind: 'unsupported', message: expect.stringMatching(/^e\.feature\.unsupported\.issue-1x\.f: /) });
        }
    });
});
