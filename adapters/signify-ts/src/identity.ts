// What hello reports as the implementation: the installed signify-ts and the commit npm resolved
// it to. Both are read from what npm installed, never from this adapter's own constants, so a
// stale install cannot report the pin it was meant to have.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { E_COMMIT, OpError, describe } from './errors.ts';

const ROOT = new URL('..', import.meta.url);
// npm's hidden lockfile records how each installed package was resolved.
const INSTALLED_LOCK = fileURLToPath(new URL('node_modules/.package-lock.json', ROOT));
const INSTALLED_PACKAGE = fileURLToPath(new URL('node_modules/signify-ts/package.json', ROOT));

export interface Implementation {
    name: string;
    version: string;
    commit: string;
}

/** Throws a harness OpError, so hello's error carries E_COMMIT as its own code. */
export function implementation(lockPath = INSTALLED_LOCK, packagePath = INSTALLED_PACKAGE): Implementation {
    let resolved: unknown;
    let version: unknown;
    try {
        resolved = JSON.parse(readFileSync(lockPath, 'utf8')).packages?.['node_modules/signify-ts']?.resolved;
        version = JSON.parse(readFileSync(packagePath, 'utf8')).version;
    } catch (err) {
        throw new OpError('harness', `${E_COMMIT}: The installed signify-ts could not be identified: ${describe(err)}`);
    }
    const commit = typeof resolved === 'string' ? /#([0-9a-f]{40})$/.exec(resolved)?.[1] : undefined;
    if (commit === undefined) {
        throw new OpError(
            'harness',
            `${E_COMMIT}: npm did not record a git commit for the installed signify-ts, so the ` +
                'adapter cannot say which code it is testing. Install it from the git pin in ' +
                'package.json with npm ci.',
        );
    }
    return { name: 'signify-ts', version: `${version} (dhh1128/signify-ts fork)`, commit };
}
