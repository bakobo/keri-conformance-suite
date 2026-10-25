// acdc.issue: a keripy 1.x issuance (registry kind ptel-1x) made by signify-ts through a fresh
// KERIA agent, as signify-ts issues (this.i 3gmfsvfk). README.md says where each value comes from.
import { type Agent, salt } from './agent.ts';
import { E_MALFORMED, OpError } from './errors.ts';
import { offered } from './schemas.ts';
import type { Backend } from './verify.ts';

export const ONE_X = 'ptel-1x';
export const E_UNSUPPORTED_ISSUE = 'e.feature.unsupported.issue-1x.f';

type Request = Record<string, unknown>;

interface Asked {
    name: string;
    issuer: string;
    issuee?: string;
    schema: string;
    attributes: Record<string, unknown>;
    registry: string;
    edges?: unknown;
}

const malformed = (what: string): OpError => new OpError('harness', `${E_MALFORMED}: ${what}`);
const unsupported = (what: string): OpError => new OpError('unsupported', `${E_UNSUPPORTED_ISSUE}: ${what}`);

const isObject = (value: unknown): value is Request => typeof value === 'object' && value !== null && !Array.isArray(value);

function read(request: Request): { roles: string[]; schemas: string[]; credentials: Asked[] } {
    const roles = request.roles;
    if (!Array.isArray(roles) || roles.length === 0 || !roles.every((r) => typeof r === 'string' && r !== '') || new Set(roles).size !== roles.length) {
        throw malformed('"roles" must be a non-empty list of distinct names.');
    }
    const schemas = request.schemas;
    if (!Array.isArray(schemas) || !schemas.every((s) => typeof s === 'string' && /^(?:[0-9a-f]{2})*$/.test(s))) {
        throw malformed('"schemas" must be a list of lowercase hex strings.');
    }
    const credentials = request.credentials;
    if (
        !Array.isArray(credentials) ||
        credentials.length === 0 ||
        !credentials.every(
            (c) =>
                isObject(c) &&
                typeof c.name === 'string' &&
                c.name !== '' &&
                roles.includes(c.issuer) &&
                (c.issuee === undefined || roles.includes(c.issuee)) &&
                typeof c.schema === 'string' &&
                isObject(c.attributes) &&
                typeof c.registry === 'string',
        )
    ) {
        throw malformed('"credentials" must be a non-empty list of credentials, each naming roles the request creates.');
    }
    const asked = credentials as Asked[];
    // The issuer adds the attribute section's d, u and i; a request does not choose them.
    if (asked.some((c) => ['d', 'u', 'i'].some((label) => Object.hasOwn(c.attributes, label)))) {
        throw malformed('an attribute is labelled d, u or i, which the issuer adds.');
    }
    if (new Set(asked.map((c) => c.name)).size !== asked.length) {
        throw malformed('a credential name appears twice.');
    }
    for (const credential of asked) {
        if (credential.registry !== ONE_X) {
            throw unsupported(`signify-ts with KERIA 0.4.1 issues only into a 1.x registry (${ONE_X}), and ${JSON.stringify(credential.name)} asks for ${JSON.stringify(credential.registry)}.`);
        }
        if (credential.edges !== undefined) {
            throw unsupported('this adapter does not issue a 1.x edge section.');
        }
    }
    return { roles: roles as string[], schemas: schemas as string[], credentials: asked };
}

const hexOf = (text: string): string => Buffer.from(text, 'utf8').toString('hex');

export async function issue(request: Request, backend: Backend): Promise<unknown> {
    const { roles, schemas, credentials } = read(request);
    const urls = await backend.serveSchemas(offered(schemas));
    const agent: Agent = await backend.agent();
    for (const url of urls.values()) {
        await agent.resolveSchema(url);
    }
    // KERIA names identifiers in its URLs, so each role gets a name of the adapter's own.
    const names = new Map(roles.map((role, n) => [role, `role-${n}`]));
    const prefixes = new Map<string, string>();
    for (const [role, name] of names) {
        prefixes.set(role, await agent.identify(name));
    }
    const out: Record<string, { acdc: string; registry: string }> = {};
    for (const [n, credential] of credentials.entries()) {
        const issuer = names.get(credential.issuer) as string;
        const { regk, vcp } = await agent.registry(issuer, `registry-${n}`);
        // signify-ts adds the attribute section's d, and a.dt unless it was asked for; its salt and
        // issuee are its caller's to give.
        const a: Record<string, unknown> = { u: salt(), ...credential.attributes };
        if (credential.issuee !== undefined) {
            a.i = prefixes.get(credential.issuee);
        }
        const issued = await agent.issue(issuer, { ri: regk, s: credential.schema, a });
        if ('refused' in issued) {
            // jsonschema's message runs on with the schema it failed; its first line is why.
            return { refused: { reason: `KERIA refuses the credential signify-ts built: ${issued.refused.split('\n')[0]}` } };
        }
        out[credential.name] = { acdc: hexOf(issued.acdc), registry: hexOf(vcp + issued.iss) };
    }
    const kels: Record<string, string> = {};
    for (const [role, pre] of prefixes) {
        kels[role] = hexOf(await agent.kel(pre));
    }
    return { kels, credentials: out };
}
