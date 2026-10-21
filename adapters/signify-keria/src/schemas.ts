// Which of a request's schemas KERIA is offered. KERIA validates a credential with keripy's schema
// validator, which follows a reference wherever it points, and its container can reach the
// network, while the bundle is the whole world (adapter protocol, acdc.verify). So a schema that
// refers outside itself is one the bundle does not have, and is withheld; this is the rule the
// keripy adapter applies for the same reason (adapters/keripy/src/kcs_adapter_keripy/acdc1x.py).

// Schema keywords that name another schema to load.
const REFERENCES = new Set(['$ref', '$dynamicRef', '$recursiveRef']);
// Keywords whose value is instance data, never a schema.
const DATA_KEYWORDS = new Set(['const', 'enum', 'default', 'examples']);
// Keywords whose value maps names to subschemas: its keys are names, not keywords.
const SCHEMA_MAPS = new Set(['properties', 'patternProperties', '$defs', 'definitions', 'dependentSchemas']);
const MISSING = Symbol('missing');
// A pointer's array index longer than this names nothing a schema holds.
const MAX_INDEX_DIGITS = 9;

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** What a local reference points at in the schema (RFC 6901), or MISSING. Only "#" and "#/..." resolve. */
function pointer(root: unknown, ref: string): unknown {
    if (ref === '#') {
        return root;
    }
    if (!ref.startsWith('#/')) {
        return MISSING;
    }
    let node = root;
    for (const raw of ref.slice(2).split('/')) {
        let part: string;
        try {
            part = decodeURIComponent(raw);
        } catch {
            return MISSING;
        }
        part = part.replaceAll('~1', '/').replaceAll('~0', '~');
        if (isObject(node) && Object.hasOwn(node, part)) {
            node = node[part];
        } else if (Array.isArray(node) && /^\d+$/.test(part) && part.length <= MAX_INDEX_DIGITS && Number(part) < node.length) {
            node = node[Number(part)];
        } else {
            return MISSING;
        }
    }
    return node;
}

/**
 * Whether a schema refers to anything outside itself. The walk goes by schema position: a value
 * under a data keyword is data, and the keys of a map of subschemas are names. A local reference
 * makes whatever it points at a schema, so its target is walked too; one that does not resolve
 * reaches out, and so does a nested base URI.
 */
export function reachesOut(schema: unknown): boolean {
    const stack: unknown[] = [schema];
    const seen = new Set<unknown>();
    while (stack.length > 0) {
        const node = stack.pop();
        if (seen.has(node)) {
            continue;
        }
        seen.add(node);
        if (Array.isArray(node)) {
            stack.push(...node);
            continue;
        }
        if (!isObject(node)) {
            continue;
        }
        if (node !== schema && ('$id' in node || 'id' in node)) {
            return true;
        }
        for (const [key, value] of Object.entries(node)) {
            if (REFERENCES.has(key)) {
                const target = typeof value === 'string' ? pointer(schema, value) : MISSING;
                if (target === MISSING) {
                    return true;
                }
                stack.push(target);
            } else if (SCHEMA_MAPS.has(key) && isObject(value)) {
                stack.push(...Object.values(value));
            } else if (!DATA_KEYWORDS.has(key)) {
                stack.push(value);
            }
        }
    }
    return false;
}

/**
 * The schemas KERIA is offered, keyed by the SAID each names as its $id, each as the hex the
 * request carried. A schema that is not JSON, has no string $id, or reaches out is left out: KERIA
 * could not index it, or the bundle does not have it.
 */
export function offered(hexes: string[]): Map<string, string> {
    const out = new Map<string, string>();
    for (const hex of hexes) {
        let doc: unknown;
        try {
            doc = JSON.parse(Buffer.from(hex, 'hex').toString('utf8'));
        } catch {
            continue;
        }
        if (isObject(doc) && typeof doc.$id === 'string' && /^[A-Za-z0-9_-]+$/.test(doc.$id) && !reachesOut(doc)) {
            out.set(doc.$id, hex);
        }
    }
    return out;
}
