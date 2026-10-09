import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { OpError } from '../src/errors.ts';
import { implementation } from '../src/identity.ts';

const root = new URL('..', import.meta.url);
const read = (rel: string) => JSON.parse(readFileSync(new URL(rel, root), 'utf8'));

describe('implementation identity', () => {
    it('names the installed signify-ts and the commit npm resolved it to', () => {
        const pkg = read('node_modules/signify-ts/package.json');
        const id = implementation();
        expect(id.name).toBe('signify-ts');
        expect(id.version).toBe(`${pkg.version} (dhh1128/signify-ts fork)`);
        expect(id.commit).toMatch(/^[0-9a-f]{40}$/);
    });

    it('reports the commit package.json pins, so a stale install cannot pass for the pin', () => {
        const spec: string = read('package.json').dependencies['signify-ts'];
        expect(spec).toMatch(/^git\+https:\/\/github\.com\/dhh1128\/signify-ts\.git#[0-9a-f]{40}$/);
        expect(implementation().commit).toBe(spec.split('#')[1]);
    });

    it('agrees with package-lock.json', () => {
        const lock = read('package-lock.json');
        const resolved: string = lock.packages['node_modules/signify-ts'].resolved;
        expect(resolved.endsWith(`#${implementation().commit}`)).toBe(true);
    });

    function fixture(lock: unknown, pkg: unknown = { version: '9.9.9' }) {
        const dir = mkdtempSync(join(tmpdir(), 'kcs-signify-'));
        const lockPath = join(dir, 'lock.json');
        const pkgPath = join(dir, 'package.json');
        writeFileSync(lockPath, JSON.stringify(lock));
        writeFileSync(pkgPath, JSON.stringify(pkg));
        return { lockPath, pkgPath };
    }

    it('refuses to guess when the installed lockfile has no commit for signify-ts', () => {
        const { lockPath, pkgPath } = fixture({ packages: { 'node_modules/signify-ts': { resolved: 'https://registry.npmjs.org/signify-ts/-/signify-ts-0.4.0.tgz' } } });
        expect(() => implementation(lockPath, pkgPath)).toThrowError(/^e\.env\.dependency\.signify-commit\.f: /);
        expect(() => implementation(lockPath, pkgPath)).toThrowError(OpError);
    });

    it('refuses when signify-ts is missing from the installed lockfile', () => {
        const { lockPath, pkgPath } = fixture({ packages: {} });
        expect(() => implementation(lockPath, pkgPath)).toThrowError(/^e\.env\.dependency\.signify-commit\.f: /);
    });

    it('refuses when the installed lockfile is not there', () => {
        expect(() => implementation('/nonexistent/lock.json', '/nonexistent/package.json')).toThrowError(
            /^e\.env\.dependency\.signify-commit\.f: /,
        );
        expect(() => implementation('/nonexistent/lock.json', '/nonexistent/package.json')).toThrowError(OpError);
    });

    it('reads a fixture lockfile', () => {
        const sha = 'a'.repeat(40);
        const { lockPath, pkgPath } = fixture({ packages: { 'node_modules/signify-ts': { resolved: `git+ssh://git@github.com/dhh1128/signify-ts.git#${sha}` } } });
        expect(implementation(lockPath, pkgPath)).toEqual({ name: 'signify-ts', version: '9.9.9 (dhh1128/signify-ts fork)', commit: sha });
    });
});
