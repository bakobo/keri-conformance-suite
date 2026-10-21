// acdc.verify: one bundle judged by a fresh KERIA agent, whose verdict the adapter reads back
// through signify-ts. this.i 3gmfsvfk records the design; README.md says where each value comes
// from.
import type { Agent } from './agent.ts';
import { E_MALFORMED, OpError } from './errors.ts';
import { offered } from './schemas.ts';

// keripy 1.x's issuance and revocation events, with and without backers.
const STATES: Record<string, string> = { iss: 'issued', bis: 'issued', rev: 'revoked', brv: 'revoked' };
// A 1.x version string: protocol, major and minor, kind, then the serialized size in hex.
const VERSION_1 = /^\{"v":"ACDC10JSON([0-9a-f]{6})_"/;
// What may follow the body: CESR text-domain attachments, which are base64url characters and
// count codes. Another JSON body, or anything else, is not one ACDC with its attachments.
const ATTACHMENTS = /^[A-Za-z0-9_-]*$/;

export const REASONS = {
    valid: "KERIA's verifier saved the credential",
    invalid: "KERIA's verifier did not save the credential; KERIA's API does not say whether it refused it or holds it in escrow",
    stalled: "KERIA's parser did not reach the end of the bundle, so the presented stream was not taken whole",
    unreadable: 'the presented stream is not one ACDC 1.x body, whose d the adapter can read, followed only by text-domain attachments',
    expected: "the credential's schema is not the one the validator expects",
} as const;

type Request = Record<string, unknown>;

/** What verify needs: a fresh agent for the request, and a way to offer it the request's schemas. */
export interface Backend {
    agent(): Promise<Agent>;
    /** Serve exactly these schemas (SAID to hex) and return the data OOBI URL of each, as KERIA reaches it. */
    serveSchemas(schemas: Map<string, string>): Promise<Map<string, string>>;
}

const malformed = (what: string): OpError => new OpError('harness', `${E_MALFORMED}: ${what}`);

function hex(value: unknown, field: string): Uint8Array {
    if (typeof value !== 'string' || !/^(?:[0-9a-f]{2})*$/.test(value)) {
        throw malformed(`"${field}" must hold lowercase hex strings.`);
    }
    return Buffer.from(value, 'hex');
}

function streams(request: Request, field: string): Uint8Array[] {
    const value = request[field];
    if (!Array.isArray(value)) {
        throw malformed(`"${field}" must be a list.`);
    }
    return value.map((entry) => {
        if (typeof entry !== 'object' || entry === null) {
            throw malformed(`Each entry of "${field}" must be an object with a "stream".`);
        }
        return hex((entry as Request).stream, field);
    });
}

/** The d of the ACDC 1.x body the stream begins with, read through its version string, or undefined. */
export function presentedSaid(stream: Uint8Array, whole = false): string | undefined {
    const text = Buffer.from(stream).toString('latin1');
    const match = VERSION_1.exec(text);
    if (match === null) {
        return undefined;
    }
    const size = parseInt(match[1], 16);
    if (size > stream.length || (whole && !ATTACHMENTS.test(text.slice(size)))) {
        return undefined;
    }
    try {
        const body = JSON.parse(Buffer.from(stream.subarray(0, size)).toString('utf8'));
        return typeof body.d === 'string' ? body.d : undefined;
    } catch {
        return undefined;
    }
}

function registry(said: string, status: unknown): unknown {
    if (typeof status !== 'object' || status === null) {
        return null;
    }
    const { ri, s, d, et } = status as Record<string, unknown>;
    if (typeof ri !== 'string' || typeof s !== 'string' || !/^[0-9a-f]+$/.test(s) || typeof d !== 'string' || typeof et !== 'string' || !Object.hasOwn(STATES, et)) {
        return null;
    }
    return { rd: ri, n: parseInt(s, 16), d, td: said, ts: STATES[et] };
}

export async function verify(request: Request, backend: Backend): Promise<unknown> {
    const kels = streams(request, 'kels');
    const registries = streams(request, 'registry');
    const acdcs = streams(request, 'acdcs');
    const presented = request.presented;
    if (typeof presented !== 'object' || presented === null) {
        throw malformed('"presented" must be an object.');
    }
    const stream = hex((presented as Request).stream, 'presented');
    const schemas = request.schemas;
    if (!Array.isArray(schemas) || !schemas.every((s) => typeof s === 'string')) {
        throw malformed('"schemas" must be a list of hex strings.');
    }
    schemas.forEach((s) => hex(s, 'schemas'));
    const expected = request.expect_schema;
    if (expected !== undefined && (typeof expected !== 'string' || expected === '')) {
        throw malformed('"expect_schema", when present, must be a non-empty string.');
    }

    // The presented stream must be one ACDC and its attachments; KERIA would save a credential from
    // the front of a longer stream, which is not what was presented.
    const said = presentedSaid(stream, true);
    if (said === undefined) {
        return { verdict: 'invalid', reason: REASONS.unreadable, registry: null, edges: [] };
    }
    const urls = await backend.serveSchemas(offered(schemas as string[]));
    const agent = await backend.agent();
    for (const url of urls.values()) {
        await agent.resolveSchema(url);
    }
    // keripy's databases are keyed by SAID, so a far node with the presented credential's own SAID
    // would let a copy delivered there stand in for what was presented. It is not a far node of the
    // presented credential, and it is not delivered (as in the keripy adapter).
    const far = acdcs.filter((each) => presentedSaid(each) !== said);
    let settled = true;
    for (const each of [...kels, ...registries, ...far, stream]) {
        await agent.deliver(each);
        // Once KERIA's parser stalls on a stream it cannot finish, nothing after it is parsed, and
        // waiting again would only spend the runner's time.
        settled = settled && (await agent.settle());
    }
    // A second settle after the last stream: KERIA's escrow pass runs once per loop, so it has run
    // at least once after everything delivered when the second marker is seen.
    settled = settled && (await agent.settle());
    const credential = await agent.credential(said);
    const head = credential === undefined ? null : registry(said, credential.status);
    // A credential saved while KERIA's parser stalled was saved from a presented stream KERIA did
    // not take whole, which is not what was presented.
    let why: keyof typeof REASONS = !settled ? 'stalled' : credential !== undefined ? 'valid' : 'invalid';
    if (why === 'valid' && expected !== undefined && (credential?.sad as Request | undefined)?.s !== expected) {
        why = 'expected';
    }
    return { verdict: why === 'valid' ? 'valid' : 'invalid', reason: REASONS[why], registry: head, edges: [] };
}
