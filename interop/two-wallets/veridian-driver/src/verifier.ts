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

async function maybeGrant(client: SignifyClient, said: string, ms: number) {
  try { return await until(`grant ${said}`, async () => {
    const response = await client.notifications().list(0, 99);
    return response.notes.find((n: any) => n.a?.r === '/exn/ipex/grant' && n.a?.d === said);
  }, ms); }
  catch { return undefined; }
}

async function record(client: SignifyClient, wallet: string, notification: any, expected: any,
                      seen: Set<string>, chain?: { apply: string; agree: string; verifier: string }) {
  const grant = await client.exchanges().get(notification.a.d);
  if (grant.exn.d !== notification.a.d || grant.exn.r !== '/ipex/grant')
    throw new Error(`${wallet} grant notification does not name a logged grant exchange.`);
  const sender = grant.exn.i;
  if (sender !== expected.holder) throw new Error(`Grant sender ${sender} differs from holder ${expected.holder}.`);
  if (chain) {
    if (grant.exn.p !== chain.agree) throw new Error('Veridian grant does not follow the verifier agreement.');
    const agreement = await client.exchanges().get(grant.exn.p);
    const offer = await client.exchanges().get(agreement.exn.p);
    if (agreement.exn.d !== chain.agree || agreement.exn.r !== '/ipex/agree' ||
        agreement.exn.i !== chain.verifier || offer.exn.r !== '/ipex/offer' ||
        offer.exn.i !== expected.holder || offer.exn.p !== chain.apply)
      throw new Error('Veridian grant prior chain does not lead to the verifier apply.');
  }
  const carried = grant.exn.e?.acdc;
  if (carried?.d !== expected.said || carried?.i !== expected.issuer ||
      carried?.a?.i !== expected.holder || carried?.s !== expected.schema)
    throw new Error(`${wallet} grant does not embed the issued credential.`);
  const heldBefore = (await client.credentials().list({ limit: 100 })).some((item: any) =>
    item.sad?.d === expected.said);
  if (wallet === 'heti' && heldBefore)
    throw new Error('Verifier already held the credential before admitting the heti grant.');
  if (wallet === 'veridian' && !heldBefore)
    throw new Error('Verifier lost the credential before admitting the Veridian grant.');
  const [admit, sigs, atc] = await client.ipex().admit({
    senderName: 'verifier', recipient: sender, grantSaid: grant.exn.d,
    message: `G17 admit ${wallet}`,
  });
  if (admit.ked.p !== grant.exn.d)
    throw new Error(`${wallet} admit does not name the logged grant in its prior field.`);
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
    admit_said: admit.ked.d, fresh_admission: !heldBefore,
    grant_logged: true, embedded_acdc: carried.d, admit_prior: admit.ked.p,
  };
  if (result.issuer !== expected.issuer || result.issuee !== expected.holder ||
      result.schema !== expected.schema || result.tel_status !== 'iss')
    throw new Error(`${wallet} credential or TEL differs from the M2 issuance: ${JSON.stringify(result)}`);
  await writeFile(path.join(out, `m3-${wallet}.json`), JSON.stringify(result, null, 2) + '\n');
  seen.add(grant.exn.d);
  return result;
}

async function proof(expected: any) {
  await rm(path.join(out, 'm4.json'), { force: true });
  const veridian = JSON.parse(await readFile(path.join(out, 'm3-veridian.json'), 'utf8'));
  const heti = JSON.parse(await readFile(path.join(out, 'm3-heti.json'), 'utf8'));
  if (veridian.said !== expected.said || heti.said !== expected.said ||
      veridian.sender !== expected.holder || heti.sender !== expected.holder ||
      !veridian.grant_logged || !heti.grant_logged ||
      veridian.admit_prior !== veridian.grant_said || heti.admit_prior !== heti.grant_said ||
      veridian.fresh_admission !== false || heti.fresh_admission !== true)
    throw new Error('Both verified presentations of the expected credential are required for M4.');
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
    holder_aid_in_heti: heti.sender,
    verifier_saw: { veridian: veridian.said, heti: heti.said },
  };
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
  const delivered = await until('heti delivery', async () => {
    try { return JSON.parse(await readFile(path.join(out, 'heti-delivery.json'), 'utf8')); }
    catch { return undefined; }
  }, 180_000);
  if (!delivered.posted || typeof delivered.grant_said !== 'string')
    throw new Error('heti did not post a signed grant for admission.');
  const bytes = await readFile(path.join(out, 'heti-grant.cesr'));
  const version = bytes.toString('ascii', 0, 32).match(/^\{"v":"KERI10JSON([0-9a-fA-F]{6})_"/);
  if (!version) throw new Error('heti grant has no KERI 1.x JSON version header.');
  const grantBody = JSON.parse(bytes.subarray(0, parseInt(version[1], 16)).toString('utf8'));
  if (grantBody.d !== delivered.grant_said || grantBody.r !== '/ipex/grant' ||
      grantBody.i !== expected.holder || grantBody.e?.acdc?.d !== expected.said)
    throw new Error('heti delivery does not name its signed grant and expected credential.');
  // The verifier must encounter this credential through heti's grant first.
  if ((await client.credentials().list({ limit: 100 })).some((item: any) => item.sad?.d === expected.said))
    throw new Error('Verifier held the credential before heti presented it.');
  let hetiNote = await maybeGrant(client, delivered.grant_said, 20_000);
  if (!hetiNote) {
    const response = await fetch('http://127.0.0.1:3902/', {
      method: 'PUT', headers: { 'CESR-DESTINATION': aid }, body: bytes,
    });
    delivered.raw_put_status = response.status;
    delivered.raw_put_body = (await response.text()).slice(0, 1000);
    hetiNote = await maybeGrant(client, delivered.grant_said, 20_000);
  }
  if (!hetiNote) {
    delivered.delivered = false;
    delivered.verifier_notifications = (await client.notifications().list(0, 99)).notes.map((n: any) =>
      ({ route: n.a?.r, said: n.a?.d, id: n.i }));
    delivered.reason = 'KERIA accepted the signed grant but produced no matching /exn/ipex/grant notification.';
    await writeFile(path.join(out, 'heti-delivery.json'), JSON.stringify(delivered, null, 2) + '\n');
    throw new Error(delivered.reason);
  }
  await record(client, 'heti', hetiNote, expected, seen);
  delivered.delivered = true;
  await writeFile(path.join(out, 'heti-delivery.json'), JSON.stringify(delivered, null, 2) + '\n');
  console.log(`Verifier admitted heti grant ${hetiNote.a.d}`);

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
  const veridianNote = await until('Veridian grant', async () =>
    notes(client, '/exn/ipex/grant', seen), 180_000);
  await record(client, 'veridian', veridianNote, expected, seen,
    { apply: apply.ked.d, agree: agree.ked.d, verifier: aid });
  console.log(`Verifier admitted Veridian grant ${veridianNote.a.d}`);
  await proof(expected);
}

main().catch(async (error) => {
  console.error(error);
  await writeFile(path.join(out, 'verifier-error.txt'), String(error) + '\n');
  process.exitCode = 1;
});
