// Adapter protocol v1 over stdio: one JSON request per line in, one JSON response per line out.
// handleLine never throws and always resolves to exactly one response line. Requests are answered
// one at a time, in order, because they share one KERIA.
import { readFileSync } from 'node:fs';

import { bootAgent } from './agent.ts';
import {
    E_EXCEPTION,
    E_MALFORMED,
    E_OVERSIZE,
    E_UNDECLARED_OP,
    E_UNKNOWN_OP,
    E_VERSION,
    OpError,
    describe,
} from './errors.ts';
import { implementation } from './identity.ts';
import { type Keria, SCHEMA_PORT, serveSchemas, startKeria } from './keria.ts';
import { type Backend, verify } from './verify.ts';

export const PROTOCOL = 1;
export const ADAPTER_NAME = 'kcs-adapter-signify-keria';
export const ADAPTER_VERSION: string = JSON.parse(
    readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
).version;
export const OPERATIONS = ['acdc.verify'] as const;
/** Drawn from profiles/features.json; README.md says why each is declared. */
export const FEATURES = [
    'acdc.keripy-1x',
    'acdc.ptel-1x',
    'cesr.genus-1.00',
    'cesr.serialization.json',
    'crypto.ed25519',
    'kel.basic',
    'keri.version-1.x',
] as const;
const UNDECLARED = new Set(['cesr.parse', 'cesr.encode', 'keri.process', 'keri.emit', 'exn.verify', 'acdc.issue', 'acdc.present']);

/** The longest request line the adapter reads, in bytes, not counting its newline. */
export const MAX_REQUEST_LINE = 64 * 1024 * 1024;

/** What the adapter does with KERIA, replaceable so tests need no Docker. */
export interface Deps {
    /** The session's KERIA, started on first use. */
    keria(): Promise<Keria>;
    implementation(keria: Keria): ReturnType<typeof implementation>;
    backend(keria: Keria): Backend;
}

/** What session uses, replaceable so tests need no Docker. */
export const SESSION_PARTS = { start: startKeria as () => Promise<Keria>, serveSchemas, bootAgent };

/** Starts KERIA once per session, on the first request that needs it, and returns the same one after. */
export function session(onStart: (keria: Keria) => void = () => {}, parts: typeof SESSION_PARTS = SESSION_PARTS): Deps {
    let started: Promise<Keria> | undefined;
    return {
        keria() {
            started ??= parts.start().then((keria) => {
                onStart(keria);
                return keria;
            });
            return started;
        },
        implementation,
        backend: (keria) => ({
            agent: () => parts.bootAgent(keria),
            async serveSchemas(schemas) {
                await parts.serveSchemas(keria, schemas);
                // KERIA reaches the schema server inside its own container.
                return new Map([...schemas.keys()].map((said) => [said, `http://127.0.0.1:${SCHEMA_PORT}/oobi/${said}`]));
            },
        }),
    };
}

type Request = Record<string, unknown>;
type Response = Record<string, unknown>;

const errorResponse = (id: unknown, kind: string, message: string): Response => ({ id, error: { kind, message } });

async function hello(request: Request, deps: Deps): Promise<unknown> {
    const offered = Array.isArray(request.supported) ? request.supported : [request.protocol];
    if (!offered.some((v) => v === PROTOCOL)) {
        throw new OpError(
            'unsupported',
            `${E_VERSION}: This adapter implements adapter protocol version ${PROTOCOL} only, and ` +
                `the runner offered ${JSON.stringify(offered)}.`,
        );
    }
    return {
        protocol: PROTOCOL,
        adapter: { name: ADAPTER_NAME, version: ADAPTER_VERSION },
        implementation: deps.implementation(await deps.keria()),
        operations: [...OPERATIONS],
        features: [...FEATURES],
        composes: [],
    };
}

async function perform(op: string, request: Request, deps: Deps): Promise<unknown> {
    switch (op) {
        case 'hello':
            return hello(request, deps);
        case 'acdc.verify':
            return verify(request, deps.backend(await deps.keria()));
    }
    if (UNDECLARED.has(op)) {
        throw new OpError('unsupported', `${E_UNDECLARED_OP}: This adapter does not implement ${op} and did not declare it in hello.`);
    }
    throw new OpError('harness', `${E_UNKNOWN_OP}: ${JSON.stringify(op)} is not an operation of adapter protocol version ${PROTOCOL}.`);
}

async function respond(id: number, request: Request, deps: Deps): Promise<Response> {
    const op = request.op;
    if (typeof op !== 'string') {
        return errorResponse(id, 'harness', `${E_MALFORMED}: The request has no string "op".`);
    }
    try {
        return { id, result: await perform(op, request, deps) };
    } catch (err) {
        if (err instanceof OpError) {
            return errorResponse(id, err.kind, err.message);
        }
        return errorResponse(id, 'harness', `${E_EXCEPTION}: An exception escaped while handling ${op}: ${describe(err)}`);
    }
}

/** Answer one request line (without its newline). */
export async function handleLine(line: string, deps: Deps): Promise<string> {
    let request: unknown;
    try {
        request = JSON.parse(line);
    } catch {
        request = undefined;
    }
    let response: Response;
    if (typeof request !== 'object' || request === null || Array.isArray(request)) {
        response = errorResponse(null, 'harness', `${E_MALFORMED}: The request line is not a UTF-8 JSON object.`);
    } else {
        const id = (request as Request).id;
        response =
            // A safe integer, because JSON.parse rounds a larger one and the response would not
            // echo the id the runner sent.
            typeof id === 'number' && Number.isSafeInteger(id) && id >= 0
                ? await respond(id, request as Request, deps)
                : errorResponse(
                      null,
                      'harness',
                      `${E_MALFORMED}: The request has no usable "id"; it must be a non-negative integer no larger than 2^53 - 1.`,
                  );
    }
    return JSON.stringify(response);
}

const notUtf8 = (): string =>
    JSON.stringify(errorResponse(null, 'harness', `${E_MALFORMED}: The request line is not valid UTF-8.`));

// fatal: a line that is not UTF-8 is refused rather than read with replacement characters.
const utf8 = new TextDecoder('utf-8', { fatal: true });

/** The line as text, or undefined when it is not UTF-8. */
function decodeLine(bytes: Buffer): string | undefined {
    try {
        return utf8.decode(bytes);
    } catch {
        return undefined;
    }
}

function oversize(maxLine: number): string {
    return JSON.stringify(
        errorResponse(null, 'harness', `${E_OVERSIZE}: The request line is longer than ${maxLine} bytes, the most this adapter reads.`),
    );
}

/**
 * Answer each request line until end of input. A line is held only up to maxLine bytes; the rest
 * of a longer one is dropped as it arrives and the line is answered with an error.
 */
export async function serve(
    input: AsyncIterable<Buffer | string>,
    write: (line: string) => unknown,
    deps: Deps,
    maxLine: number = MAX_REQUEST_LINE,
): Promise<void> {
    let parts: Buffer[] = [];
    let held = 0;
    let over = false;
    let pending = false;
    const finish = async () => {
        const text = over ? undefined : decodeLine(Buffer.concat(parts));
        await write((over ? oversize(maxLine) : text === undefined ? notUtf8() : await handleLine(text, deps)) + '\n');
        parts = [];
        held = 0;
        over = false;
        pending = false;
    };
    const take = (piece: Buffer) => {
        if (piece.length === 0) return;
        pending = true;
        if (over) return;
        if (held + piece.length > maxLine) {
            over = true;
            parts = [];
            held = 0;
            return;
        }
        parts.push(piece);
        held += piece.length;
    };
    for await (const chunk of input) {
        let buf = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk;
        let nl = buf.indexOf(0x0a);
        while (nl !== -1) {
            take(buf.subarray(0, nl));
            pending = true;
            await finish();
            buf = buf.subarray(nl + 1);
            nl = buf.indexOf(0x0a);
        }
        take(buf);
    }
    if (pending) {
        await finish();
    }
}
