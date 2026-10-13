import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import {
  ready, Controller, Tier, KeyManager, Identifier, Serder, Siger,
  messagize, Decrypter, Cipher, MtrDex,
} from 'signify-ts';

const root = path.resolve(__dirname, '..', 'interop', 'two-wallets');
const brans = [
  'abcdefghijklmnopqrstu',
  '1234567890abcdefghijk',
  'zxywvutsrqponmlkjihgf',
];

async function vector(bran: string) {
  const controller = new Controller(bran, Tier.low);
  const manager = new KeyManager(controller.salter);
  const identifier = new Identifier({
    manager,
    pidx: 0,
    fetch: async () => { throw new Error('Vectors must remain offline.'); },
  });
  const data = await identifier.createInceptionData('offline-holder');
  if (!data.salty?.sxlt) throw new Error('Signify did not produce a salty.sxlt.');
  const signer = controller.salter.signer(MtrDex.Ed25519_Seed, true, undefined, Tier.low);
  const aeid = signer.verfer.qb64;
  const decrypter = new Decrypter({}, signer.qb64b);
  const salt = decrypter.decrypt(null, new Cipher({ qb64: data.salty.sxlt })).qb64;
  const serder = new Serder(data.icp);
  const attached = messagize(serder, data.sigs.map((signature) => new Siger({ qb64: signature })));
  return {
    bran,
    sxlt: data.salty.sxlt,
    aeid,
    salt_qb64_decrypted: salt,
    keys: data.icp.k,
    ndigs: data.icp.n,
    icp_raw: Buffer.from(attached).toString('utf8'),
    prefix: data.icp.i,
  };
}

async function main() {
  await ready();
  const vectors = [];
  for (const bran of brans) vectors.push(await vector(bran));
  const output: Record<string, unknown> = {
    signifyTsCommit: '62a646f1eb67c30c8f1aecfe628d81dd693b60f2',
    vectors,
  };
  try {
    const m1 = JSON.parse(await readFile(path.join(root, 'out', 'm1.json'), 'utf8'));
    const kel = await readFile(path.join(root, 'out', 'm1-kel.cesr'), 'utf8');
    output.witnessed = { bran: m1.bran, sxlt: m1.sxlt, aid: m1.aid, kel_cesr: kel };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  await mkdir(path.join(root, 'vectors'), { recursive: true });
  const file = path.join(root, 'vectors', 'signify-salty-62a646f.json');
  await writeFile(file, JSON.stringify(output, null, 2) + '\n');
  console.log(file);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
