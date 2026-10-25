// A session whose KERIA and agents are fakes, so protocol tests need no Docker.
import type { Agent } from '../src/agent.ts';
import { E_KERIA_START, OpError } from '../src/errors.ts';
import type { Keria } from '../src/keria.ts';
import { type Deps, session } from '../src/protocol.ts';

export const KERIA: Keria = {
    container: 'cid',
    image: 'weboftrust/keria@sha256:00',
    admin: 'http://127.0.0.1:41',
    http: 'http://127.0.0.1:42',
    boot: 'http://127.0.0.1:43',
    schemas: 'http://127.0.0.1:44',
    keria: '0.4.1',
    keri: '1.2.14',
};

/** An ACDC 1.x body with a correct version string, as hex. */
export function acdcHex(d: string): string {
    const draft = (size: number) => JSON.stringify({ v: `ACDC10JSON${size.toString(16).padStart(6, '0')}_`, d });
    return Buffer.from(draft(draft(0).length)).toString('hex');
}

export interface FakeOptions {
    credential?: Record<string, unknown>;
    exported?: string;
    startFails?: boolean;
    served?: Map<string, string>[];
    starts?: { count: number };
}

export function fakeDeps(options: FakeOptions = {}, onStart?: (keria: Keria) => void): Deps {
    const agent: Agent = {
        resolveSchema: async () => true,
        deliver: async () => {},
        settle: async () => true,
        credential: async () => options.credential,
        exported: async () => options.exported,
        identify: async (name) => `E${name}`,
        registry: async () => ({ regk: 'ERegistry', vcp: '{"v":"KERI10JSON"}' }),
        issue: async () => ({ acdc: '{"v":"ACDC10JSON"}', iss: '{"v":"KERI10JSON"}' }),
        kel: async (pre) => `{"i":"${pre}"}`,
    };
    return session(onStart, {
        async start() {
            if (options.starts) options.starts.count += 1;
            if (options.startFails) throw new OpError('harness', `${E_KERIA_START}: no Docker here.`);
            return KERIA;
        },
        async serveSchemas(_keria, schemas) {
            options.served?.push(schemas);
        },
        bootAgent: async () => agent,
    });
}
