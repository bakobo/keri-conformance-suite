import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { restoreSecureStorage, snapshotSecureStorage } from './secure-storage-shim';

const root = path.resolve(__dirname, '..', 'interop', 'two-wallets');
const file = path.join(root, 'out', 'veridian-state.json');

export async function saveState(agent: any) {
  const records: [string, unknown][] = [];
  await agent.storageSession.session.forEach((value: unknown, key: string) => {
    records.push([key, value]);
  });
  await writeFile(file, JSON.stringify({
    secure: snapshotSecureStorage(), records,
  }, null, 2) + '\n');
}

export async function restoreState(agent: any) {
  const state = JSON.parse(await readFile(file, 'utf8'));
  if (!Array.isArray(state.records) || !state.secure)
    throw new Error('Saved Veridian wallet state is incomplete.');
  restoreSecureStorage(state.secure);
  for (const [key, value] of state.records)
    await agent.storageSession.session.set(key, value);
}
