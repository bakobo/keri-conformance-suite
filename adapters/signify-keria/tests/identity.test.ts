import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { OpError } from '../src/errors.ts';
import { IMPLEMENTATION_NAME, implementation } from '../src/identity.ts';
import type { Keria } from '../src/keria.ts';

const root = new URL('..', import.meta.url);
const read = (rel: string) => JSON.parse(readFileSync(new URL(rel, root), 'utf8'));
const keria = { keria: '0.4.1', keri: '1.2.14' } as Keria;

describe('implementation identity', () => {
    it('names the installed signify-ts, the commit npm resolved it to, and the running KERIA', () => {
        const pkg = read('node_modules/signify-ts/package.json');
        const id = implementation(keria);
        expect(id.name).toBe(IMPLEMENTATION_NAME);
        expect(id.version).toBe(`${pkg.version} with KERIA 0.4.1 (keripy 1.2.14)`);
        expect(id.commit).toMatch(/^[0-9a-f]{40}$/);
    });

    it('reports the commit package.json pins, which is the signify-ts 0.4.1 release tag', () => {
        const spec: string = read('package.json').dependencies['signify-ts'];
        expect(spec).toBe('git+https://github.com/WebOfTrust/signify-ts.git#5a174b5456c2d256493f9991ac4ae73857ff4fce');
        expect(implementation(keria).commit).toBe(spec.split('#')[1]);
    });

    it('agrees with package-lock.json', () => {
        const resolved: string = read('package-lock.json').packages['node_modules/signify-ts'].resolved;
        expect(resolved.endsWith(`#${implementation(keria).commit}`)).toBe(true);
    });

    function fixture(lock: unknown, pkg: unknown = { version: '9.9.9' }) {
        const dir = mkdtempSync(join(tmpdir(), 'kcs-signify-keria-'));
        const lockPath = join(dir, 'lock.json');
        const pkgPath = join(dir, 'package.json');
        writeFileSync(lockPath, JSON.stringify(lock));
        writeFileSync(pkgPath, JSON.stringify(pkg));
        return { lockPath, pkgPath };
    }

    it.each([
        ['a lockfile with no packages', {}],
        ['no entry for signify-ts', { packages: {} }],
        ['a registry tarball instead of a commit', { packages: { 'node_modules/signify-ts': { resolved: 'https://registry.npmjs.org/signify-ts/-/signify-ts-0.4.1.tgz' } } }],
    ])('refuses %s', (_name, lock) => {
        const { lockPath, pkgPath } = fixture(lock);
        expect(() => implementation(keria, lockPath, pkgPath)).toThrow(OpError);
        expect(() => implementation(keria, lockPath, pkgPath)).toThrow(/^e\.env\.dependency\.signify-commit\.f: npm did not record/);
    });

    it('refuses an install it cannot read', () => {
        expect(() => implementation(keria, '/nonexistent/lock.json', '/nonexistent/package.json')).toThrow(/could not be identified/);
    });
});
