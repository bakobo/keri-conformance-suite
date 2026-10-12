import 'fake-indexeddb/auto';
import { Crypto } from '@peculiar/webcrypto';
import { TextDecoder, TextEncoder } from 'node:util';
import { ReadableStream } from 'node:stream/web';
import { mkdir, writeFile } from 'node:fs/promises';
import { AsyncLocalStorage } from 'node:async_hooks';
import path from 'node:path';

// Match Veridian's setupTests.ts before loading its core modules.
Reflect.set(globalThis, 'TextDecoder', TextDecoder);
Reflect.set(globalThis, 'TextEncoder', TextEncoder);
Reflect.set(globalThis, 'ReadableStream', ReadableStream);
Object.defineProperty(globalThis, 'crypto', { value: new Crypto(), configurable: true });
globalThis.structuredClone = (value) => JSON.parse(JSON.stringify(value));

// Poller timers should not keep a completed one-step CLI alive. Async context
// confines unref() to Veridian's polling chains, leaving operation timers alone.
const pollingContext = new AsyncLocalStorage<boolean>();
const originalSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = ((handler, delay, ...args) => {
  const timer = originalSetTimeout(handler, delay, ...args);
  if (pollingContext.getStore()) timer.unref();
  return timer;
}) as typeof setTimeout;

const root = path.resolve(__dirname, '..', 'interop', 'two-wallets');
const veridianCommit = 'd41ce8811f790b9883176539794e68d36fa66bba';
const signifyTsCommit = '62a646f1eb67c30c8f1aecfe628d81dd693b60f2';

export async function runM1(keepPolling = false) {
  const [{ Agent }, { SecureStorage, KeyStoreKeys }, { ready }] = await Promise.all([
    import('@veridian/core/agent/agent'),
    import('@veridian/core/storage/secureStorage/secureStorage'),
    import('signify-ts'),
  ]);
  await ready();
  const agent = Agent.agent;
  await agent.setupLocalDependencies();
  const { bran, mnemonic } = agent.getBranAndMnemonic();
  await SecureStorage.set(KeyStoreKeys.SIGNIFY_BRAN, bran);
  await agent.bootAndConnect({ bootUrl: 'http://127.0.0.1:3903', url: 'http://127.0.0.1:3901' });
  const poller = agent.keriaNotifications;
  poller.startPolling();
  pollingContext.run(true, () => {
    void poller.pollNotifications();
    void poller.pollLongOperations();
  });
  try {
    const result = await agent.identifiers.createIdentifier({ displayName: 'holder', theme: 0 });
    const aid = result.identifier;
    const deadline = Date.now() + 120_000;
    let oobi = '';
    while (Date.now() < deadline) {
      const response = await fetch(`http://127.0.0.1:5642/oobi/${aid}/witness`);
      if (response.ok) {
        oobi = response.url;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    if (!oobi) throw new Error(`Holder ${aid} was not witnessed before the deadline.`);
    const hab = await agent.client.identifiers().get(aid);
    const sxlt = hab.salty?.sxlt;
    if (!sxlt) throw new Error(`Holder ${aid} has no salty.sxlt.`);
    const output = {
      bran, mnemonic, aid, oobi, sxlt,
      keriaAgentPre: agent.client.agent.pre,
      veridianCommit, signifyTsCommit,
    };
    await mkdir(path.join(root, 'out'), { recursive: true });
    await writeFile(path.join(root, 'out', 'm1.json'), JSON.stringify(output, null, 2) + '\n');
    console.log(`Created and witnessed holder ${aid}`);
    return { agent, poller, output };
  } finally {
    if (!keepPolling) poller.stopPolling();
  }
}

if (!process.env.G17_EMBED_M1) {
  runM1().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
