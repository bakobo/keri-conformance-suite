import { spawn } from 'node:child_process';
import { readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import path from 'node:path';

const root = path.resolve(__dirname, '..', 'interop', 'two-wallets');
const out = path.join(root, 'out');
const fixtures = path.join(root, 'fixtures', 'm2');
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function until<T>(label: string, action: () => Promise<T | undefined>, timeout = 120_000): Promise<T> {
  const deadline = Date.now() + timeout;
  let last: unknown;
  while (Date.now() < deadline) {
    try { const result = await action(); if (result) return result; }
    catch (error) { last = error; }
    await delay(500);
  }
  throw new Error(`${label} did not complete before the deadline. Last error: ${last}`);
}

async function kel(aid: string): Promise<Buffer> {
  const response = await fetch(`http://127.0.0.1:5642/oobi/${aid}/witness`);
  if (!response.ok) throw new Error(`Witness KEL for ${aid}: HTTP ${response.status}`);
  return Buffer.from(await response.arrayBuffer());
}

async function main() {
  // Fake IndexedDB and the secure-storage shim live in this process. Running
  // M1 here keeps the same Veridian Agent and local metadata through admit.
  process.env.G17_EMBED_M1 = '1';
  const { runM1 } = await import('./m1');
  const { agent, poller, output: holder } = await runM1(true);
  await rm(path.join(out, 'm2.json'), { force: true });
  await rm(fixtures, { recursive: true, force: true });
  await rm(path.join(out, 'issuer.json'), { force: true });
  await rm(path.join(out, 'holder-ready'), { force: true });
  const child = spawn(path.join(root, 'veridian-driver', 'bin', 'issuer'), [], {
    stdio: 'inherit', env: process.env,
  });
  try {
    const issued = await until('issuer grant', async () => {
      if (child.exitCode !== null) throw new Error(`Issuer exited with ${child.exitCode}`);
      try { return JSON.parse(await readFile(path.join(out, 'issuer.json'), 'utf8')); }
      catch { return undefined; }
    }, 180_000);
    await agent.connections.connectByOobiUrl(issued.issuerOobi, holder.aid);
    await until('issuer connection', async () => {
      const connection = await agent.connections.getConnectionById(issued.issuer, false, holder.aid);
      return connection?.serviceEndpoints?.length ? connection : undefined;
    });
    // Veridian's resolver assumes every optional `e` schema definition has a
    // fixed child schema. SAM's optional edge definitions do not. The issued
    // ACDC has no e section, so resolve only this schema through the same
    // Veridian OOBI service and retain the original resolver otherwise.
    const ipex = agent.ipexCommunications as any;
    const originalResolve = ipex.recursiveSchemaResolve.bind(ipex);
    ipex.recursiveSchemaResolve = async (base: string, said: string) => {
      if (said !== issued.schema) return originalResolve(base, said);
      await agent.connections.resolveOobi(base + said, true);
      return agent.client.schemas().get(said);
    };
    await agent.connections.resolveOobi(`http://127.0.0.1:7723/oobi/${issued.schema}`, true);
    await writeFile(path.join(out, 'holder-ready'), 'connected\n');
    const note = await until('IPEX grant notification', async () =>
      (await agent.keriaNotifications.getNotifications()).find((n: any) => n.a?.r === '/exn/ipex/grant'));
    const grant = await agent.client.exchanges().get(note.a.d);
    const issuedDate = grant.exn.e.acdc.a.issuedDate.value;
    if (typeof issuedDate !== 'string' || Number.isNaN(Date.parse(issuedDate)))
      throw new Error('SAM issuedDate.value is missing or invalid.');
    const saveMetadata = ipex.saveAcdcMetadataRecord.bind(ipex);
    ipex.saveAcdcMetadataRecord = (holderRecord: any, credentialId: string,
      dateTime: string | undefined, ...rest: any[]) =>
      saveMetadata(holderRecord, credentialId, dateTime ?? issuedDate, ...rest);
    await agent.ipexCommunications.admitAcdcFromGrant(note.id);
    await until('Veridian credential listing', async () =>
      (await agent.credentials.getCredentials()).find((c: any) => c.id === issued.said));
    await mkdir(fixtures, { recursive: true });
    const credential = await agent.client.credentials().get(issued.said, true);
    if (typeof credential !== 'string' || !credential.includes(issued.said))
      throw new Error('Holder CESR export did not contain credential SAID.');
    await writeFile(path.join(fixtures, 'credential.cesr'), credential, 'utf8');
    await writeFile(path.join(fixtures, 'holder-kel.cesr'), await kel(holder.aid));
    await writeFile(path.join(fixtures, 'issuer-kel.cesr'), await kel(issued.issuer));
    await writeFile(path.join(fixtures, 'holder.json'), JSON.stringify({
      bran: holder.bran, sxlt: holder.sxlt, aid: holder.aid,
    }, null, 2) + '\n');
    const result = {
      said: issued.said, issuer: issued.issuer, registry: issued.registry,
      schema: issued.schema, holder: holder.aid,
    };
    await writeFile(path.join(out, 'm2.json'), JSON.stringify(result, null, 2) + '\n');
    console.log(`Veridian holds ${issued.said}`);
  } finally {
    poller.stopPolling();
    child.kill('SIGTERM');
    await rm(path.join(out, 'holder-ready'), { force: true });
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
