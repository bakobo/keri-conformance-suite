import { readFile, writeFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { SignifyClient, Tier, ready } from 'signify-ts';

const root = path.resolve(__dirname, '..', 'interop', 'two-wallets');
const out = path.join(root, 'out');
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const wits = [
  'BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha',
  'BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM',
  'BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX',
  'BM35JN8XeJSEfpxopjn5jr7tAHCE5749f0OobhMLCorE',
  'BIj15u5V11bkbtAxMA7gcNJZcax-7TgaBMLsQnMHpYHP',
  'BF2rZTW79z4IXocYRQnjjsOuvFUQv-ptCf8Yltd7PfsM',
];

async function until<T>(label: string, action: () => Promise<T | undefined>, ms = 120_000): Promise<T> {
  const deadline = Date.now() + ms;
  let last: unknown;
  while (Date.now() < deadline) {
    try { const result = await action(); if (result) return result; }
    catch (error) { last = error; }
    await sleep(500);
  }
  throw new Error(`${label} timed out. Last error: ${last}`);
}

async function wait(client: SignifyClient, op: any) {
  const result = await client.operations().wait(await op);
  if (!result.done || result.error) throw new Error(`KERIA operation failed: ${JSON.stringify(result)}`);
  return result;
}

async function notes(client: SignifyClient, route: string, seen: Set<string>) {
  const response = await client.notifications().list(0, 99);
  return response.notes.find((n: any) => n.a?.r === route && !seen.has(n.a.d));
}

async function maybeNote(client: SignifyClient, route: string, seen: Set<string>, ms: number) {
  try { return await until(route, async () => notes(client, route, seen), ms); }
  catch { return undefined; }
}

async function record(client: SignifyClient, wallet: string, notification: any, expected: any,
                      seen: Set<string>) {
  const grant = await client.exchanges().get(notification.a.d);
  const sender = grant.exn.i;
  if (sender !== expected.holder) throw new Error(`Grant sender ${sender} differs from holder ${expected.holder}.`);
  const carried = grant.exn.e?.acdc;
  if (carried?.d !== expected.said || carried?.i !== expected.issuer ||
      carried?.a?.i !== expected.holder || carried?.s !== expected.schema)
    throw new Error(`${wallet} grant does not embed the issued credential.`);
  const [admit, sigs, atc] = await client.ipex().admit({
    senderName: 'verifier', recipient: sender, grantSaid: grant.exn.d,
    message: `G17 admit ${wallet}`,
  });
  await wait(client, client.ipex().submitAdmit('verifier', admit, sigs, atc, [sender]));
  const credential = await until(`${wallet} credential`, async () => {
    const got = await client.credentials().get(expected.said);
    return got?.sad?.d === expected.said ? got : undefined;
  });
  const sad = credential.sad;
  const tel = await client.credentials().state(expected.registry, expected.said);
  const result = {
    said: sad.d, issuer: sad.i, issuee: sad.a.i, schema: sad.s,
    tel_status: tel.et, sender, grant_said: grant.exn.d,
    admit_said: admit.ked.d,
  };
  if (result.issuer !== expected.issuer || result.issuee !== expected.holder ||
      result.schema !== expected.schema || result.tel_status !== 'iss')
    throw new Error(`${wallet} credential or TEL differs from the M2 issuance: ${JSON.stringify(result)}`);
  await writeFile(path.join(out, `m3-${wallet}.json`), JSON.stringify(result, null, 2) + '\n');
  seen.add(grant.exn.d);
  return result;
}

async function proof(expected: any, veridian: any, heti: any | null) {
  const issuerInfo = JSON.parse(await readFile(path.join(out, 'issuer.json'), 'utf8'));
  const issuer = new SignifyClient('http://127.0.0.1:3901', issuerInfo.bran,
    Tier.low, 'http://127.0.0.1:3903');
  await issuer.connect();
  const listed = await issuer.credentials().list({ limit: 100 });
  const inRegistry = listed.filter((item: any) => item.sad?.ri === expected.registry);
  const full = await issuer.credentials().get(expected.said);
  const cesr = await issuer.credentials().get(expected.said, true);
  const current = await issuer.credentials().state(expected.registry, expected.said);
  const count = (cesr.match(/"t":"iss"/g) || []).length;
  if (inRegistry.length !== 1 || inRegistry[0].sad.d !== expected.said ||
      count !== 1 || full.iss.t !== 'iss' || String(full.iss.s) !== '0' ||
      current.et !== 'iss' || String(current.s) !== '0')
    throw new Error(`Issuer proof failed: registry count=${inRegistry.length}, CESR iss count=${count}, TEL=${JSON.stringify(current)}`);
  const result = {
    said: expected.said, issued_count: inRegistry.length,
    tel: [{ t: full.iss.t, s: full.iss.s, d: full.iss.d }],
    holder_aid_in_veridian: expected.holder,
    holder_aid_in_heti: heti?.sender ?? JSON.parse(await readFile(path.join(out, 'heti-holder.json'), 'utf8')).aid,
    verifier_saw: { veridian: veridian.said, heti: heti?.said ?? null },
  };
  if (heti && (heti.said !== veridian.said || heti.sender !== veridian.sender))
    throw new Error('The two presentations do not name the same credential and holder.');
  await writeFile(path.join(out, 'm4.json'), JSON.stringify(result, null, 2) + '\n');
}

async function main() {
  await ready();
  const expected = JSON.parse(await readFile(path.join(out, 'm2.json'), 'utf8'));
  const holder = JSON.parse(await readFile(path.join(out, 'm1.json'), 'utf8'));
  const issuerInfo = JSON.parse(await readFile(path.join(out, 'issuer.json'), 'utf8'));
  const client = new SignifyClient('http://127.0.0.1:3901',
    process.env.G17_VERIFIER_BRAN || 'g17verifierpassphrase26', Tier.low,
    'http://127.0.0.1:3903');
  const boot = await client.boot();
  if (!boot.ok && boot.status !== 409) throw new Error(`Verifier boot failed: ${boot.status}`);
  await client.connect();
  const created = await client.identifiers().create('verifier', { wits, toad: 4 });
  await wait(client, created.op());
  const aid = created.serder.pre;
  const role = await client.identifiers().addEndRole('verifier', 'agent', client.agent.pre);
  await wait(client, role.op());
  const oobi = (await client.oobis().get('verifier', 'agent')).oobis[0];
  if (!oobi) throw new Error('Verifier agent OOBI was not published.');
  await wait(client, client.oobis().resolve(holder.oobi, 'holder'));
  await wait(client, client.oobis().resolve(
    `http://127.0.0.1:3902/oobi/${holder.aid}/agent/${holder.keriaAgentPre}`, 'holder-agent'));
  await wait(client, client.oobis().resolve(issuerInfo.issuerOobi, 'issuer'));
  await wait(client, client.oobis().resolve(
    `http://127.0.0.1:7723/oobi/${expected.schema}`, 'sam-core'));
  await writeFile(path.join(out, 'verifier.json'), JSON.stringify({ aid, oobi,
    keriaAgentPre: client.agent.pre }, null, 2) + '\n');
  await until('Veridian verifier connection', async () => {
    try { await readFile(path.join(out, 'verifier-holder-ready')); return true; }
    catch { return undefined; }
  });

  const seen = new Set<string>();
  const [apply, applySigs] = await client.ipex().apply({
    senderName: 'verifier', recipient: holder.aid, schemaSaid: expected.schema,
    message: 'G17 SEDI presentation request',
  });
  await wait(client, client.ipex().submitApply('verifier', apply, applySigs, [holder.aid]));
  const offer = await until('Veridian offer', async () => notes(client, '/exn/ipex/offer', seen));
  seen.add(offer.a.d);
  const offerExn = await client.exchanges().get(offer.a.d);
  if (offerExn.exn.e?.acdc?.d !== expected.said) throw new Error('Veridian offered another credential.');
  const [agree, agreeSigs] = await client.ipex().agree({
    senderName: 'verifier', recipient: holder.aid, offerSaid: offer.a.d,
    message: 'G17 agree',
  });
  await wait(client, client.ipex().submitAgree('verifier', agree, agreeSigs, [holder.aid]));
  const first = await until('Veridian grant', async () => notes(client, '/exn/ipex/grant', seen), 180_000);
  const veridian = await record(client, 'veridian', first, expected, seen);
  console.log(`Verifier admitted Veridian grant ${first.a.d}`);

  let heti: any | null = null;
  const delivered = await until('heti delivery', async () => {
    try { return JSON.parse(await readFile(path.join(out, 'heti-delivery.json'), 'utf8')); }
    catch { return undefined; }
  }, 180_000);
  if (delivered.posted) {
    // The first POST was delivered with CESR-DESTINATION. If KERIA accepted
    // but did not notify, feed the identical signed stream to its raw PUT
    // parser. This changes transport only, never heti's signed bytes.
    let second = await maybeNote(client, '/exn/ipex/grant', seen, 20_000);
    if (!second) {
      const bytes = await readFile(path.join(out, 'heti-grant.cesr'));
      const response = await fetch('http://127.0.0.1:3902/', {
        method: 'PUT', headers: { 'CESR-DESTINATION': aid }, body: bytes,
      });
      delivered.raw_put_status = response.status;
      delivered.raw_put_body = (await response.text()).slice(0, 1000);
      second = await maybeNote(client, '/exn/ipex/grant', seen, 20_000);
    }
    if (second) {
      heti = await record(client, 'heti', second, expected, seen);
      delivered.delivered = true;
      console.log(`Verifier admitted heti grant ${second.a.d}`);
    } else {
      delivered.delivered = false;
      delivered.verifier_notifications = (await client.notifications().list(0, 99)).notes.map((n: any) =>
        ({ route: n.a?.r, said: n.a?.d, id: n.i }));
      delivered.reason = 'KERIA accepted the signed grant but produced no /exn/ipex/grant notification.';
    }
  }
  await writeFile(path.join(out, 'heti-delivery.json'), JSON.stringify(delivered, null, 2) + '\n');
  await proof(expected, veridian, heti);
}

main().catch(async (error) => {
  console.error(error);
  await writeFile(path.join(out, 'verifier-error.txt'), String(error) + '\n');
  process.exitCode = 1;
});
