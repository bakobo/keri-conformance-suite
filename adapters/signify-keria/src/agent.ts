// One KERIA agent, booted and driven by signify-ts for one acdc.verify request, so that nothing a
// request delivers is seen by another. What verify.ts needs from it is the Agent interface; this
// module is the only place that touches signify-ts's client.
import {
    Diger,
    MtrDex,
    Siger,
    SignifyClient,
    Signer,
    Tier,
    incept,
    messagize,
    randomPasscode,
} from 'signify-ts';

import { E_KERIA, OpError, describe } from './errors.ts';
import type { Keria } from './keria.ts';

export interface Agent {
    /** Have KERIA resolve a data OOBI; resolves whether KERIA took the schema, and fails if KERIA did not answer. */
    resolveSchema(url: string): Promise<boolean>;
    /** Put bytes, unchanged, onto the end of the agent's own parser's input. */
    deliver(bytes: Uint8Array): Promise<void>;
    /**
     * Deliver a key event of an identifier nothing else names, and wait until KERIA holds its key
     * state: everything delivered before it has then been parsed. Resolves false if that does not
     * happen by the deadline.
     */
    settle(): Promise<boolean>;
    /** The credential KERIA's verifier saved under this SAID, or undefined if it saved none. */
    credential(said: string): Promise<Record<string, unknown> | undefined>;
    /** KERIA's CESR export of the credential it saved under this SAID, or undefined if it saved none. */
    exported(said: string): Promise<string | undefined>;
}

/** How long one OOBI resolution or one settle may take, in milliseconds. */
export const WAIT = 10_000;
const POLL = 50;

/** The parts of signify-ts's client this module uses, replaceable in tests. */
export interface Client {
    agent: { pre: string } | null;
    boot(): Promise<Response>;
    connect(): Promise<void>;
    oobis(): { resolve(url: string): Promise<{ name: string }> };
    operations(): { wait(op: { name: string }, options: { signal: AbortSignal }): Promise<unknown> };
    keyStates(): { get(pre: string): Promise<unknown> };
    credentials(): { get(said: string, includeCESR: boolean): Promise<unknown> };
}

export interface AgentDeps {
    client: (keria: Keria) => Client;
    /** How long any one call to KERIA may take, in milliseconds. */
    limit: number;
    fetch: typeof fetch;
    sleep: (ms: number) => Promise<void>;
    now: () => number;
}

export const DEFAULT_AGENT: AgentDeps = {
    limit: WAIT,
    client: (keria) => new SignifyClient(keria.admin, randomPasscode(), Tier.low, keria.boot) as unknown as Client,
    fetch: (...args) => fetch(...args),
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    now: () => Date.now(),
};

/** A signed inception of a fresh transferable identifier with no witnesses, and its prefix. */
export function sentinel(): { pre: string; message: Uint8Array } {
    const current = new Signer({});
    const next = new Signer({});
    const serder = incept({
        keys: [current.verfer.qb64],
        ndigs: [new Diger({ code: MtrDex.Blake3_256 }, next.verfer.qb64b).qb64],
    });
    const siger = current.sign(new TextEncoder().encode(serder.raw), 0) as Siger;
    return { pre: serder.pre, message: messagize(serder, [siger]) };
}

/** The promise's outcome, or a failure once ms pass: a peer that never answers cannot hold a request. */
export function within<T>(promise: Promise<T>, ms: number): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    const late = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`KERIA did not answer within ${ms} ms`)), ms);
    });
    return Promise.race([promise, late]).finally(() => clearTimeout(timer));
}

const failed = (what: string, err: unknown): OpError =>
    new OpError('harness', `${E_KERIA}: KERIA failed while the adapter ${what}: ${describe(err)}`);

/** signify-ts reports an operation KERIA finished with an error this way (Operations.wait). */
// KERIA writes exactly this when its OOBI resolver marks the OOBI failed, which for a data OOBI
// is a schema whose $id is not its SAID; any other failure reads differently.
const refusedOperation = (err: unknown): boolean => /^Operation '[^']*' failed \[Code 500\]: resolving OOBI \S+ failed$/.test(describe(err));

/** signify-ts reports a refused request as an Error whose message carries the HTTP status. */
const notFound = (err: unknown): boolean => / - 404 /.test(describe(err));

export async function bootAgent(keria: Keria, deps: AgentDeps = DEFAULT_AGENT): Promise<Agent> {
    const client = deps.client(keria);
    try {
        await within(client.boot(), deps.limit);
        await within(client.connect(), deps.limit);
    } catch (err) {
        throw failed('booted an agent', err);
    }
    const pre = client.agent?.pre;
    if (typeof pre !== 'string') {
        throw failed('booted an agent', 'signify-ts connected without an agent identifier');
    }

    async function deliver(bytes: Uint8Array): Promise<void> {
        let response: Response;
        try {
            // The one call the adapter makes itself, so the one it can cancel; signify-ts's client
            // takes no signal for its own requests, which within only stops waiting for.
            response = await within(deps.fetch(`${keria.http}/`, {
                signal: AbortSignal.timeout(deps.limit),
                method: 'PUT',
                headers: { 'CESR-DESTINATION': pre as string, 'Content-Type': 'application/cesr' },
                body: Buffer.from(bytes),
            }), deps.limit);
        } catch (err) {
            throw failed('delivered a stream', err);
        }
        if (response.status !== 204) {
            throw failed('delivered a stream', `HTTP ${response.status}`);
        }
    }

    async function read(said: string, cesr: boolean): Promise<unknown> {
        try {
            return await within(client.credentials().get(said, cesr), deps.limit);
        } catch (err) {
            if (notFound(err)) {
                return undefined;
            }
            throw failed('read a credential', err);
        }
    }

    return {
        async resolveSchema(url) {
            try {
                const op = await within(client.oobis().resolve(url), deps.limit);
                await within(client.operations().wait(op, { signal: AbortSignal.timeout(deps.limit) }), deps.limit);
                return true;
            } catch (err) {
                // KERIA marks the operation failed when it will not take the schema (its $id is not
                // its SAID), which is a schema the bundle does not have. Anything else, a refused
                // request or no answer in time, is KERIA failing, not a judgement.
                if (refusedOperation(err)) {
                    return false;
                }
                throw failed('resolved a schema', err);
            }
        },
        deliver,
        async settle() {
            const { pre: marker, message } = sentinel();
            await deliver(message);
            const deadline = deps.now() + WAIT;
            for (;;) {
                let states: unknown;
                try {
                    states = await within(client.keyStates().get(marker), deps.limit);
                } catch (err) {
                    throw failed('read a key state', err);
                }
                if (Array.isArray(states) && states.length > 0) {
                    return true;
                }
                if (deps.now() > deadline) {
                    return false;
                }
                await deps.sleep(POLL);
            }
        },
        async credential(said) {
            return (await read(said, false)) as Record<string, unknown> | undefined;
        },
        async exported(said) {
            return (await read(said, true)) as string | undefined;
        },
    };
}
