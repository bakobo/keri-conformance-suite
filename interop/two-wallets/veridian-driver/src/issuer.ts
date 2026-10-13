import { createServer } from 'node:http';
import { readFile, writeFile, mkdir, access } from 'node:fs/promises';
import path from 'node:path';
import { SignifyClient, Tier, ready, Saider, Salter, Serder, interact, b,
  versify, Ident, Ilks, Serials } from 'signify-ts';

const root = path.resolve(__dirname, '..', 'interop', 'two-wallets');
const out = path.join(root, 'out');
const schemaPath = path.join(root, 'schemas', 'sedi-core-1x.schema.json');
const witnessPrefixes = [
  'BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha',
  'BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM',
  'BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX',
  'BM35JN8XeJSEfpxopjn5jr7tAHCE5749f0OobhMLCorE',
  'BIj15u5V11bkbtAxMA7gcNJZcax-7TgaBMLsQnMHpYHP',
  'BF2rZTW79z4IXocYRQnjjsOuvFUQv-ptCf8Yltd7PfsM',
];

async function wait(client: SignifyClient, op: any) {
  const result = await client.operations().wait(await op);
  if (result.error || !result.done) throw new Error(`KERIA operation failed: ${JSON.stringify(result)}`);
  return result;
}

// signify-ts Credentials.issue unconditionally adds a.dt. SAM's unchanged
// attribute section rejects it, so construct its three issuance events with
// the same signify primitives and a separate TEL timestamp.
async function issueSam(client: SignifyClient, registry: string, schema: string,
  issuer: string, attributes: Record<string, unknown>) {
  const hab = await client.identifiers().get('issuer');
  const keeper = client.manager!.get(hab);
  const [, subject] = Saider.saidify({ d: '', ...attributes });
  const [, acdc] = Saider.saidify({
    v: versify(Ident.ACDC, undefined, Serials.JSON, 0), d: '',
    u: new Salter({}).qb64, i: issuer, ri: registry, s: schema, a: subject,
  });
  const [, iss] = Saider.saidify({
    v: versify(Ident.KERI, undefined, Serials.JSON, 0), t: Ilks.iss,
    d: '', i: acdc.d, s: '0', ri: registry,
    dt: new Date().toISOString().replace('Z', '000+00:00'),
  });
  const anc = interact({
    pre: issuer, sn: parseInt(hab.state.s, 16) + 1,
    data: [{ i: iss.i, s: iss.s, d: iss.d }], dig: hab.state.d,
    version: undefined, kind: undefined,
  });
  const sigs = await keeper.sign(b(anc.raw));
  const response = await client.fetch('/identifiers/issuer/credentials', 'POST', {
    acdc, iss, ixn: anc.ked, sigs, [keeper.algo]: keeper.params(),
  }, new Headers({ Accept: 'application/json+cesr' }));
  return { acdc: new Serder(acdc), iss: new Serder(iss), anc, op: await response.json() };
}

async function main() {
  await ready();
  const holder = JSON.parse(await readFile(path.join(out, 'm1.json'), 'utf8'));
  const schemaRaw = await readFile(schemaPath);
  const schema = JSON.parse(schemaRaw.toString());
  const said = schema.$id;
  const server = createServer((req, res) => {
    if (req.url !== `/oobi/${said}`) { res.writeHead(404).end(); return; }
    res.writeHead(200, { 'Content-Type': 'application/schema+json' }).end(schemaRaw);
  });
  await new Promise<void>((resolve) => server.listen(7723, '127.0.0.1', resolve));
  try {
    const bran = process.env.G17_ISSUER_BRAN || 'g17issuerpassphrase2026';
    const client = new SignifyClient('http://127.0.0.1:3901', bran, Tier.low, 'http://127.0.0.1:3903');
    const boot = await client.boot();
    if (!boot.ok && boot.status !== 409) throw new Error(`Issuer boot failed: ${boot.status}`);
    await client.connect();
    const created = await client.identifiers().create('issuer', { wits: witnessPrefixes, toad: 4 });
    await wait(client, created.op());
    const issuer = created.serder.pre;
    const role = await client.identifiers().addEndRole('issuer', 'agent', client.agent.pre);
    await wait(client, role.op());
    const issuerOobi = (await client.oobis().get('issuer', 'agent')).oobis[0];
    if (!issuerOobi) throw new Error('Issuer agent OOBI was not published.');
    await wait(client, client.oobis().resolve(holder.oobi, 'holder'));
    const holderAgentOobi = `http://127.0.0.1:3902/oobi/${holder.aid}/agent/${holder.keriaAgentPre}`;
    await wait(client, client.oobis().resolve(holderAgentOobi, 'holder-agent'));
    await wait(client, client.oobis().resolve(`http://127.0.0.1:7723/oobi/${said}`, 'sam-core'));
    const registryResult = await client.registries().create({ name: 'issuer', registryName: 'sam-core' });
    await wait(client, registryResult.op());
    const registry = registryResult.regser.pre;

    const block = (value: string) => Saider.saidify({ d: '', u: new Salter({}).qb64, value })[1];
    const attributes = {
      u: new Salter({}).qb64, i: holder.aid, primary: true,
      givenName: block('Ada'), middleName: block(''), familyName: block('Lovelace'),
      nameSuffix: block(''), birthDate: block('1990-01-01'),
      facialImageProof: block(''), legalPresenceStatus: block('citizen'),
      issuedDate: block('2026-10-12'), expirationDate: block('2027-10-12'),
    };
    const issued = await issueSam(client, registry, said, issuer, attributes);
    await wait(client, issued.op);
    const credentialSaid = issued.acdc.ked.d;
    const full = await client.credentials().get(credentialSaid);
    await mkdir(out, { recursive: true });
    await writeFile(path.join(out, 'issuer.json'), JSON.stringify({
      bran, issuer, issuerOobi, registry, schema: said, said: credentialSaid,
      nestedSaidification: 'client-side; credentials().issue saidifies a and ACDC only, and inserts forbidden a.dt',
    }, null, 2) + '\n');
    const readyFile = path.join(out, 'holder-ready');
    const deadline = Date.now() + 120_000;
    while (Date.now() < deadline) {
      try { await access(readyFile); break; } catch { await new Promise((r) => setTimeout(r, 200)); }
    }
    await access(readyFile);
    // The inline schema URL is a Veridian core convention. The pinned Signify
    // grant helper accepts only `m`, so add the URL at its exchange constructor.
    const exchanges = client.exchanges();
    const makeExchange = exchanges.createExchangeMessage.bind(exchanges);
    exchanges.createExchangeMessage = ((hab: any, route: string, payload: any, ...rest: any[]) =>
      makeExchange(hab, route, route === '/ipex/grant'
        ? { ...payload, oobiUrl: 'http://127.0.0.1:7723/oobi' } : payload, ...rest)) as typeof exchanges.createExchangeMessage;
    // client.exchanges() creates a new wrapper, so bind this temporary method
    // through the instance used by ipex().grant below.
    const originalExchanges = client.exchanges.bind(client);
    client.exchanges = (() => exchanges) as typeof client.exchanges;
    try {
      const [grant, sigs, atc] = await client.ipex().grant({
        senderName: 'issuer', recipient: holder.aid,
        acdc: new Serder(full.sad), iss: new Serder(full.iss),
        anc: new Serder(full.anc), ancAttachment: full.ancAttachment,
      });
      await wait(client, client.ipex().submitGrant('issuer', grant, sigs, atc, [holder.aid]));
    } finally { client.exchanges = originalExchanges; }
    console.log(`Issued and granted ${credentialSaid}`);
    await new Promise<void>(() => {});
  } finally { server.close(); }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
