import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const mode = process.argv[2] as 'm1' | 'vectors';
if (mode !== 'm1' && mode !== 'vectors') {
  console.error('Expected m1 or vectors.');
  process.exit(2);
}
const driver = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const build = spawnSync(process.execPath, [path.join(driver, 'build.cjs'), mode], {
  stdio: 'inherit',
  env: process.env,
});
if (build.status !== 0) process.exit(build.status ?? 1);

const bundle = path.resolve(driver, '../../../.ignored', `veridian-${mode}.cjs`);
const run = spawnSync(process.execPath, [bundle], { stdio: 'inherit', env: process.env });
process.exit(run.status ?? 1);
