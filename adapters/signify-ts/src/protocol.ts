// Adapter protocol v1 over stdio: one JSON request per line in, one JSON response per line out.
// handleLine never throws and always returns exactly one response line.
import { readFileSync } from 'node:fs';

import { encode, parseStream } from './cesr.ts';
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

export const PROTOCOL = 1;
export const ADAPTER_NAME = 'kcs-adapter-signify-ts';
export const ADAPTER_VERSION: string = JSON.parse(
    readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
).version;
export const OPERATIONS = ['cesr.parse', 'cesr.encode'] as const;
/** Drawn from profiles/features.json; README.md says why each is or is not declared. */
export const FEATURES = [
    'cesr.genus-1.00',
    'cesr.genus-2.00',
    'cesr.item-extents',
    'cesr.serialization.json',
    'keri.version-1.x',
    'keri.version-2.x',
] as const;
const UNDECLARED = new Set(['keri.process', 'keri.emit', 'acdc.verify', 'exn.verify']);

/** The longest request line the adapter reads, in bytes, not counting its newline. */
export const MAX_REQUEST_LINE = 64 * 1024 * 1024;

/** What handleLine calls, replaceable so tests can make each one fail. */
export const DEFAULT_DEPS = { parseStream, encode, implementation };
export type Deps = typeof DEFAULT_DEPS;

type Request = Record<string, unknown>;
type Response = Record<string, unknown>;

const errorResponse = (id: unknown, kind: string, message: string): Response => ({ id, error: { kind, message } });

function hello(request: Request, deps: Deps): unknown {
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
        implementation: deps.implementation(),
        operations: [...OPERATIONS],
        features: [...FEATURES],
        composes: [],
    };
}

function hexField(request: Request, field: string): Uint8Array {
    const text = request[field];
    if (typeof text !== 'string' || !/^(?:[0-9a-f]{2})*$/.test(text)) {
        throw new OpError('harness', `${E_MALFORMED}: "${field}" must be a lowercase hex string.`);
    }
    return Buffer.from(text, 'hex');
}

function encodeOp(request: Request, deps: Deps): unknown {
    const { code, domain } = request;
    if (typeof code !== 'string' || code === '') {
        throw new OpError('harness', `${E_MALFORMED}: "code" must be a non-empty string.`);
    }
    if (domain !== 'text' && domain !== 'binary') {
        throw new OpError('harness', `${E_MALFORMED}: "domain" must be "text" or "binary".`);
    }
    return deps.encode(code, hexField(request, 'raw'), domain);
}

function perform(op: string, request: Request, deps: Deps): unknown {
    switch (op) {
        case 'hello':
            return hello(request, deps);
        case 'cesr.parse':
            return deps.parseStream(hexField(request, 'stream'));
        case 'cesr.encode':
            return encodeOp(request, deps);
    }
    if (UNDECLARED.has(op)) {
        throw new OpError('unsupported', `${E_UNDECLARED_OP}: This adapter does not implement ${op} and did not declare it in hello.`);
    }
    throw new OpError('harness', `${E_UNKNOWN_OP}: ${JSON.stringify(op)} is not an operation of adapter protocol version ${PROTOCOL}.`);
}

function respond(id: number, request: Request, deps: Deps): Response {
    const op = request.op;
    if (typeof op !== 'string') {
        return errorResponse(id, 'harness', `${E_MALFORMED}: The request has no string "op".`);
    }
    try {
        return { id, result: perform(op, request, deps) };
    } catch (err) {
        if (err instanceof OpError) {
            return errorResponse(id, err.kind, err.message);
        }
        return errorResponse(id, 'harness', `${E_EXCEPTION}: An exception escaped while handling ${op}: ${describe(err)}`);
    }
}

/** Answer one request line (without its newline). */
export function handleLine(line: string, deps: Deps = DEFAULT_DEPS): string {
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
            typeof id === 'number' && Number.isInteger(id) && id >= 0
                ? respond(id, request as Request, deps)
                : errorResponse(null, 'harness', `${E_MALFORMED}: The request has no usable "id"; it must be a non-negative integer.`);
    }
    return JSON.stringify(response);
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
    maxLine: number = MAX_REQUEST_LINE,
): Promise<void> {
    let parts: Buffer[] = [];
    let held = 0;
    let over = false;
    let pending = false;
    const finish = async () => {
        await write((over ? oversize(maxLine) : handleLine(Buffer.concat(parts).toString('utf8'))) + '\n');
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
