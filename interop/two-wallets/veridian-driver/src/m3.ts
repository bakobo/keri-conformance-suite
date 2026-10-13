import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { readFile, writeFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { restoreState } from './state';

const root = path.resolve(__dirname, '..', 'interop', 'two-wallets');
const out = path.join(root, 'out');
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function until<T>(label: string, action: () => Promise<T | undefined>, timeout = 120_000): Promise<T> {
  const deadline = Date.now() + timeout;
  let last: unknown;
  while (Date.now() < deadline) {
    try { const value = await action(); if (value) return value; }
    catch (error) { last = error; }
    await pause(500);
  }
  throw new Error(`${label} timed out. Last error: ${last}`);
}

async function jsonFile(name: string): Promise<any | undefined> {
  try { return JSON.parse(await readFile(path.join(out, name), 'utf8')); }
  catch { return undefined; }
}

async function run() {
  process.env.G17_EMBED_M1 = '1';
  const { startPollers } = await import('./m1'); // Install headless globals first.
  const { Agent } = await import('@veridian/core/agent/agent');
  const agent = Agent.agent;
  await agent.setupLocalDependencies();
  await restoreState(agent);
  await agent.bootAndConnect({ bootUrl: 'http://127.0.0.1:3903', url: 'http://127.0.0.1:3901' });
  const poller = agent.keriaNotifications;
  startPollers(poller);
  const holder = await jsonFile('m1.json');
  const issued = await jsonFile('m2.json');
  if (!holder || !issued) throw new Error('M1/M2 output is missing.');
  const schemaRaw = await readFile(path.join(root, 'schemas', 'sedi-core-1x.schema.json'));
  const schemaServer = createServer((request, response) => {
    if (request.url !== `/oobi/${issued.schema}`) { response.writeHead(404).end(); return; }
    response.writeHead(200, { 'Content-Type': 'application/schema+json' }).end(schemaRaw);
  });
  await new Promise<void>((resolve, reject) => {
    schemaServer.once('error', reject);
    schemaServer.listen(7723, '127.0.0.1', resolve);
  });
  const verifier = spawn(path.join(root, 'veridian-driver', 'bin', 'verifier'), [], {
    stdio: 'inherit', env: process.env,
  });
  try {
    const identity = await until('verifier setup', async () => {
      if (verifier.exitCode !== null) throw new Error(`Verifier exited ${verifier.exitCode}`);
      return jsonFile('verifier.json');
    });
    const ipex = agent.ipexCommunications as any;
    const originalSchemaUrl = ipex.getSchemaUrl.bind(ipex);
    const originalHistory = ipex.createLinkedIpexMessageRecord.bind(ipex);
    ipex.createLinkedIpexMessageRecord = async (message: any, ...rest: any[]) => {
      let schema = message.exn.r === '/ipex/apply'
        ? message.exn.a?.s : message.exn.e?.acdc?.s;
      if (!schema && (message.exn.r === '/ipex/agree' || message.exn.r === '/ipex/admit')) {
        const previous = await agent.client.exchanges().get(message.exn.p);
        schema = previous.exn.e?.acdc?.s;
      }
      if (schema !== issued.schema ||
          ![message.exn.i, message.exn.rp].includes(identity.aid))
        return originalHistory(message, ...rest);
      ipex.getSchemaUrl = async () => 'http://127.0.0.1:7723/oobi/';
      try { return await originalHistory(message, ...rest); }
      finally { ipex.getSchemaUrl = originalSchemaUrl; }
    };
    await agent.connections.connectByOobiUrl(identity.oobi, holder.aid);
    await until('verifier connection', async () => {
      const connection = await agent.connections.getConnectionById(identity.aid, false, holder.aid);
      return connection?.serviceEndpoints?.length ? connection : undefined;
    });
    await writeFile(path.join(out, 'verifier-holder-ready'), 'connected\n');
    await agent.markSeedPhraseAsVerified();
    const exporting = spawn(path.join(root, 'veridian-driver', 'bin', 'veridian'),
      ['export'], { stdio: 'inherit', env: process.env });
    const exportExit = await new Promise<number>((resolve) =>
      exporting.on('exit', (code) => resolve(code ?? 1)));
    if (exportExit !== 0) throw new Error(`Veridian export exited ${exportExit}`);

    const heti = spawn('/home/daniel/code/bakobo/heti/.worktrees/two-wallets/.venv/bin/python',
      [path.join(root, 'py', 'heti_holder.py')], { stdio: 'inherit', env: process.env });
    const exit = await new Promise<number>((resolve) => heti.on('exit', (code) => resolve(code ?? 1)));
    if (exit !== 0) throw new Error(`heti holder exited ${exit}`);
    await until('heti admission', async () => jsonFile('m3-heti.json'), 120_000);

    const apply = await until('Veridian apply notification', async () =>
      (await agent.keriaNotifications.getNotifications()).find((note: any) =>
        note.a?.r === '/exn/ipex/apply'));
    const held = await agent.client.credentials().get(issued.said);
    await agent.ipexCommunications.offerAcdcFromApply(apply.id, held.sad);
    const presentation = await until('Veridian presentation', async () =>
      jsonFile('m3-veridian.json'), 180_000);
    const admit = await until('Veridian admit notification', async () => {
      const notifications = await agent.keriaNotifications.getNotifications();
      for (const note of notifications) {
        if (note.a?.r !== '/exn/ipex/admit') continue;
        const exchange = await agent.client.exchanges().get(note.a.d);
        if (exchange.exn.d === presentation.admit_said &&
            exchange.exn.r === '/ipex/admit' &&
            exchange.exn.p === presentation.grant_said &&
            exchange.exn.i === identity.aid)
          return exchange.exn.d as string;
      }
      return undefined;
    }, 20_000).catch(() => undefined);
    if (admit)
      await writeFile(path.join(out, 'm3-veridian-admit.json'),
        JSON.stringify({ said: admit, grant_said: presentation.grant_said }, null, 2) + '\n');
    const coreNotes = await agent.keriaNotifications.getNotifications();
    const keriaNotes: any[] = [];
    for (let start = 0; ; start += 100) {
      const page = await agent.client.notifications().list(start, start + 99);
      keriaNotes.push(...page.notes);
      if (page.notes.length === 0 || keriaNotes.length >= page.total) break;
    }
    const keriaAdmits = await Promise.all(keriaNotes
      .filter((n: any) => n.a?.r === '/exn/ipex/admit' && n.a?.d === presentation.admit_said)
      .map(async (n: any) => {
        const exchange = await agent.client.exchanges().get(n.a.d);
        return { said: exchange.exn.d, route: exchange.exn.r,
          prior: exchange.exn.p, sender: exchange.exn.i, id: n.i };
      }));
    await writeFile(path.join(out, 'm3-veridian-admit-check.json'), JSON.stringify({
      grant_said: presentation.grant_said,
      admit_said: presentation.admit_said,
      holder_received_admit: admit ?? null,
      core_admit_notifications: coreNotes.filter((n: any) => n.a?.r === '/exn/ipex/admit')
        .map((n: any) => ({ said: n.a.d, id: n.id })),
      keria_admit_notifications: keriaAdmits,
    }, null, 2) + '\n');
    console.log(`Veridian presented ${issued.said} to ${identity.aid}`);
    console.log('MILESTONE M3 reached');
    await until('M4 issuer proof', async () => jsonFile('m4.json'), 120_000);
    console.log('MILESTONE M4 reached');
  } finally {
    poller.stopPolling();
    verifier.kill('SIGTERM');
    schemaServer.close();
    await rm(path.join(out, 'holder-ready'), { force: true });
    await rm(path.join(out, 'verifier-holder-ready'), { force: true });
  }
}

run().catch((error) => { console.error(error); process.exitCode = 1; });
