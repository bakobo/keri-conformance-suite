import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { mnemonicToEntropy } from 'bip39';
import { restoreState } from './state';

const root = path.resolve(__dirname, '..', 'interop', 'two-wallets');
const out = path.join(root, 'out');

async function main() {
  process.env.G17_EMBED_M1 = '1';
  await import('./m1');
  const { Agent } = await import('@veridian/core/agent/agent');
  const agent = Agent.agent;
  await agent.setupLocalDependencies();
  await restoreState(agent);
  await agent.bootAndConnect({ bootUrl: 'http://127.0.0.1:3903', url: 'http://127.0.0.1:3901' });
  const holder = JSON.parse(await readFile(path.join(out, 'm1.json'), 'utf8'));
  const issued = JSON.parse(await readFile(path.join(out, 'm2.json'), 'utf8'));
  // Exact inverse of Agent.recoverKeriaAgent: the phrase carries a UTF-8
  // bran followed by Agent.BUFFER_ALLOC_SIZE zero bytes.
  const mnemonic = await agent.getMnemonic();
  const entropy = Buffer.from(mnemonicToEntropy(mnemonic), 'hex');
  const bran = entropy.subarray(0, -3).toString('utf8');
  if (bran.length !== 21 || !entropy.subarray(-3).equals(Buffer.alloc(3)))
    throw new Error('Veridian recovery phrase did not decode to a 21-character bran.');
  const local = await (agent as any).identifierStorage.getIdentifierMetadata(holder.aid);
  if (!local.sxlt) throw new Error('Local Veridian identifier metadata has no sxlt.');
  const credential = await agent.client.credentials().get(issued.said, true);
  if (typeof credential !== 'string' || !credential.includes(issued.said))
    throw new Error('Holder agent did not export the issued credential as CESR.');
  await writeFile(path.join(out, 'export-credential.cesr'), credential);
  await writeFile(path.join(out, 'export.json'), JSON.stringify({
    mnemonic, bran, aid: holder.aid, sxlt: local.sxlt,
    said: issued.said, sxlt_source: 'Veridian local IdentifierMetadataRecord',
    credential_source: 'holder KERIA agent via signify-ts credentials().get(said, true)',
    credential_requires_old_agent_online: true,
  }, null, 2) + '\n');
  console.log(`Exported Veridian holder ${holder.aid} and credential ${issued.said}`);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
