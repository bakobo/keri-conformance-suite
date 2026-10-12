const path = require('node:path');
const fs = require('node:fs');
const veridian = process.env.VERIDIAN_DIR || '/home/daniel/code/bakobo/veridian-wallet/.worktrees/two-wallets';
const esbuild = require(path.join(veridian, 'node_modules/esbuild'));
const root = __dirname;
const mode = process.argv[2];
if (!['m1', 'vectors'].includes(mode)) throw new Error('Expected m1 or vectors.');
const output = path.join(root, '..', '..', '..', '.ignored', `veridian-${mode}.cjs`);
fs.mkdirSync(path.dirname(output), { recursive: true });
esbuild.build({
  entryPoints: [path.join(root, 'src', `${mode}.ts`)],
  outfile: output,
  bundle: true,
  platform: 'node',
  format: 'cjs',
  target: 'node24',
  packages: 'bundle',
  nodePaths: [path.join(veridian, 'node_modules')],
  tsconfigRaw: { compilerOptions: { experimentalDecorators: true, useDefineForClassFields: false } },
  logLevel: 'warning',
  plugins: [{
    name: 'veridian-headless',
    setup(build) {
      build.onResolve({ filter: /^@veridian\// }, args => ({
        path: path.join(veridian, 'src', args.path.slice('@veridian/'.length)) + '.ts'
      }));
      build.onResolve({ filter: /^@evva\/capacitor-secure-storage-plugin$/ }, () => ({
        path: path.join(root, 'src', 'secure-storage-shim.ts')
      }));
      build.onResolve({ filter: /cardano\/walletConnect\/peerConnection$/ }, () => ({
        path: path.join(root, 'src', 'peer-connection-shim.ts')
      }));
    }
  }]
}).then(() => console.log(output)).catch(error => {
  console.error(error);
  process.exitCode = 1;
});
