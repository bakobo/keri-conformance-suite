// The KERIA this adapter tests: the pinned image, started by the adapter in Docker for one session
// and removed when the session ends. KERIA reports no version over HTTP, so the adapter starts the
// image itself and reads KERIA's and keripy's versions from inside the running container rather
// than trusting a service it did not start.
//
// Every port is published on the host's loopback interface only. KERIA listens on every interface
// inside its container, and host networking would put its admin API on the host's network.
//
// KERIA learns a schema only by resolving a data OOBI, an HTTP URL ending /oobi/<SAID>. The adapter
// cannot serve one from the host, because a container may not reach the host (a host firewall
// commonly drops that traffic), so it runs a small standard-library server inside KERIA's own
// container, SCHEMA_SERVER below, which KERIA reaches at 127.0.0.1 in its own network namespace.
// The adapter replaces the server's whole set of schemas before each request, through a published
// port, so a request's agent can resolve only the schemas its own bundle carries.
import { execFile, execFileSync } from 'node:child_process';

import { E_KERIA, E_KERIA_START, OpError, describe } from './errors.ts';

/** weboftrust/keria 0.4.1, by the digest of its multi-architecture index. */
export const KERIA_IMAGE = 'weboftrust/keria@sha256:4f728aed7e608cb5fae778682d8286a02353f310c628e145a36c31cefb1c9faf';
const PYTHON = '/keria/.venv/bin/python';
const ADMIN = 3901;
const HTTP = 3902;
const BOOT = 3903;
/** The schema server's port inside the container. */
export const SCHEMA_PORT = 7700;
const LABEL = 'kcs.adapter=signify-keria';
/** How long KERIA and the schema server get to start answering, in milliseconds. */
export const START_DEADLINE = 45_000;
const POLL = 200;
/** How long one health request may take, in milliseconds. */
export const POLL_TIMEOUT = 2_000;

export const SCHEMA_SERVER = `
import http.server, json
store = {}
class Handler(http.server.BaseHTTPRequestHandler):
    def do_PUT(self):
        size = int(self.headers.get("Content-Length", "0"))
        replacement = {said: bytes.fromhex(raw) for said, raw in json.loads(self.rfile.read(size)).items()}
        store.clear()
        store.update(replacement)
        self.send_response(204)
        self.end_headers()
    def do_GET(self):
        parts = self.path.split("/")
        raw = store.get(parts[2]) if len(parts) == 3 and parts[1] == "oobi" else None
        if raw is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/schema+json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    def log_message(self, *args):
        pass
http.server.ThreadingHTTPServer(("0.0.0.0", ${SCHEMA_PORT}), Handler).serve_forever()
`;

const VERSIONS = "import importlib.metadata as m; print(m.version('keria'), m.version('keri'))";

export interface Keria {
    container: string;
    image: string;
    /** Host URLs of KERIA's admin, CESR and boot interfaces and of the schema server. */
    admin: string;
    http: string;
    boot: string;
    schemas: string;
    keria: string;
    keri: string;
}

/** Runs docker with these arguments and resolves with its standard output. */
export type Docker = (args: string[]) => Promise<string>;

/** Runs a program as docker is run: resolves with its standard output, or fails with its standard error. */
export const runner =
    (program: string): Docker =>
    (args) =>
        new Promise((resolve, reject) => {
            execFile(program, args, { maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
                if (err) {
                    reject(new Error(`${program} ${args[0]} failed: ${stderr.trim() || err.message}`));
                } else {
                    resolve(stdout);
                }
            });
        });

export const docker: Docker = runner('docker');

export interface StartDeps {
    docker: Docker;
    fetch: typeof fetch;
    sleep: (ms: number) => Promise<void>;
    now: () => number;
    stop: (container: string) => void;
}

export const DEFAULT_START: StartDeps = {
    docker,
    fetch: (...args) => fetch(...args),
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    now: () => Date.now(),
    stop: (container) => stopKeria(container),
};

async function published(deps: StartDeps, container: string, port: number): Promise<string> {
    const line = (await deps.docker(['port', container, `${port}/tcp`])).split('\n')[0].trim();
    if (!/^127\.0\.0\.1:\d+$/.test(line)) {
        throw new Error(`Docker published container port ${port} as ${JSON.stringify(line)}, not on 127.0.0.1.`);
    }
    return `http://${line}`;
}

async function answers(deps: StartDeps, url: string, init: RequestInit = {}): Promise<boolean> {
    try {
        // Bounded, so a server that accepts the connection and never answers cannot outlast the deadline.
        return (await deps.fetch(url, { ...init, signal: AbortSignal.timeout(POLL_TIMEOUT) })).ok;
    } catch {
        return false;
    }
}

/** Start the pinned KERIA image and its schema server, and wait until both answer. */
export async function startKeria(deps: StartDeps = DEFAULT_START, image: string = KERIA_IMAGE): Promise<Keria> {
    let container: string | undefined;
    try {
        const ports = [ADMIN, HTTP, BOOT, SCHEMA_PORT].flatMap((p) => ['-p', `127.0.0.1::${p}`]);
        container = (await deps.docker(['run', '-d', '--rm', '--label', LABEL, ...ports, image, 'start'])).trim();
        await deps.docker(['exec', '-d', container, PYTHON, '-c', SCHEMA_SERVER]);
        const [keria, keri] = (await deps.docker(['exec', container, PYTHON, '-c', VERSIONS])).trim().split(' ');
        const found = {
            container,
            image,
            admin: await published(deps, container, ADMIN),
            http: await published(deps, container, HTTP),
            boot: await published(deps, container, BOOT),
            schemas: await published(deps, container, SCHEMA_PORT),
            keria,
            keri,
        };
        const deadline = deps.now() + START_DEADLINE;
        const empty = { method: 'PUT', body: '{}', headers: { 'Content-Type': 'application/json' } };
        while (!(await answers(deps, `${found.boot}/health`)) || !(await answers(deps, `${found.schemas}/`, empty))) {
            if (deps.now() > deadline) {
                throw new Error(`KERIA did not answer within ${START_DEADLINE / 1000} seconds.`);
            }
            await deps.sleep(POLL);
        }
        return found;
    } catch (err) {
        if (container !== undefined) {
            deps.stop(container);
        }
        throw new OpError('harness', `${E_KERIA_START}: The adapter could not start ${image}: ${describe(err)}`);
    }
}

/** Remove the container, synchronously, so it can run while the process exits. Never throws. */
export function stopKeria(container: string, run: typeof execFileSync = execFileSync): void {
    try {
        run('docker', ['rm', '-f', container], { stdio: 'ignore' });
    } catch {
        // Nothing more can be done while exiting; the container carries LABEL for cleanup.
    }
}

/** Replace the schema server's set with these schemas, keyed by SAID, each as hex. */
export async function serveSchemas(keria: Keria, schemas: Map<string, string>, put: typeof fetch = fetch): Promise<void> {
    let ok = false;
    let why = '';
    try {
        const response = await put(`${keria.schemas}/`, {
            method: 'PUT',
            body: JSON.stringify(Object.fromEntries(schemas)),
            headers: { 'Content-Type': 'application/json' },
        });
        ok = response.ok;
        why = `HTTP ${response.status}`;
    } catch (err) {
        why = describe(err);
    }
    if (!ok) {
        throw new OpError('harness', `${E_KERIA}: The schema server in KERIA's container refused the request's schemas: ${why}.`);
    }
}
