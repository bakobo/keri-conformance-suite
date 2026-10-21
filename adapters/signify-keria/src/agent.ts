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
    /** Have KERIA resolve a data OOBI; resolves whether KERIA finished resolving it. */
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
    operations(): { wait(op: { name: string }, options: { signal: AbortSignal }): Promise<{ done?: boolean; error?: unknown }> };
    keyStates(): { get(pre: string): Promise<unknown> };
    credentials(): { get(said: string): Promise<unknown> };
}

export interface AgentDeps {
    client: (keria: Keria) => Client;
    fetch: typeof fetch;
    sleep: (ms: number) => Promise<void>;
    now: () => number;
}

export const DEFAULT_AGENT: AgentDeps = {
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

const failed = (what: string, err: unknown): OpError =>
    new OpError('harness', `${E_KERIA}: KERIA failed while the adapter ${what}: ${describe(err)}`);

/** signify-ts reports a refused request as an Error whose message carries the HTTP status. */
const notFound = (err: unknown): boolean => / - 404 /.test(describe(err));

export async function bootAgent(keria: Keria, deps: AgentDeps = DEFAULT_AGENT): Promise<Agent> {
    const client = deps.client(keria);
    try {
        await client.boot();
        await client.connect();
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
            response = await deps.fetch(`${keria.http}/`, {
                method: 'PUT',
                headers: { 'CESR-DESTINATION': pre as string, 'Content-Type': 'application/cesr' },
                body: Buffer.from(bytes),
            });
        } catch (err) {
            throw failed('delivered a stream', err);
        }
        if (response.status !== 204) {
            throw failed('delivered a stream', `HTTP ${response.status}`);
        }
    }

    return {
        async resolveSchema(url) {
            try {
                const op = await client.oobis().resolve(url);
                const done = await client.operations().wait(op, { signal: AbortSignal.timeout(WAIT) });
                return done.done === true && done.error === undefined;
            } catch {
                return false; // a schema KERIA would not take is one the bundle does not have
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
                    states = await client.keyStates().get(marker);
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
            try {
                return (await client.credentials().get(said)) as Record<string, unknown>;
            } catch (err) {
                if (notFound(err)) {
                    return undefined;
                }
                throw failed('read a credential', err);
            }
        },
    };
}
