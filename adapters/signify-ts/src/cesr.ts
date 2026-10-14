// cesr.parse and cesr.encode, answered from signify-ts. README.md, "Where each value comes from",
// says the source of every reported value; nothing here frames CESR itself.
import { Counter, Indexer, Matter, b64ToInt, parse } from 'signify-ts';
import type { AttachmentGroup, AttachmentNode, ParseResult, Primitive } from 'signify-ts';

import {
    E_DOMAIN,
    E_ENCODE_REFUSED,
    E_GROUP_HEADER,
    E_PRIMITIVE_CODE,
    E_UNCONSUMED,
    OpError,
    describe,
} from './errors.ts';

export type Item = Record<string, string | number>;
export type ParseAnswer = { items: Item[] } | { reject: { class: string } };
export type Parser = (stream: Uint8Array) => ParseResult;

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

/** Hand the stream to signify-ts's parse() and report what it found. */
export function parseStream(stream: Uint8Array, parser: Parser = parse): ParseAnswer {
    const result = parser(stream);
    if (result.errors.length > 0) {
        // The stream in a request is complete (adapter protocol, "End of input"), so even the
        // parser's recoverable `incomplete` is final here.
        const first = result.errors[0];
        process.stderr.write(`signify-ts rejected the stream: ${first.code}: ${first.message}\n`);
        return { reject: { class: first.code } };
    }
    if (result.consumed !== stream.length) {
        throw new OpError(
            'harness',
            `${E_UNCONSUMED}: signify-ts reported no error but framed only ${result.consumed} of ` +
                `${stream.length} bytes, so the adapter cannot tell whether it accepted the stream.`,
        );
    }
    const text = (start: number, end: number) => Buffer.from(stream.subarray(start, end)).toString('latin1');
    const items: Item[] = [];
    for (const message of result.messages) {
        const { start, end } = message.span;
        items.push({
            kind: 'message',
            start,
            end,
            proto: message.proto,
            version: message.version,
            serialization: message.kind,
            size: end - start,
        });
        for (const group of message.attachments) {
            reportGroup(group, text, items);
        }
    }
    return { items };
}

type Text = (start: number, end: number) => string;

function reportGroup(group: AttachmentGroup, text: Text, items: Item[]): void {
    const { start, end } = group.span;
    if (group.genus === 2 && group.code.startsWith('-_')) {
        // A genus/version code: the parser framed it as a bodyless group whose count is the three
        // version characters read as one base64 number, major first.
        const code = text(start, end);
        const major = Math.floor(group.count / 4096);
        const minor = String(group.count % 4096).padStart(2, '0');
        items.push({ kind: 'genus', start, end, code, genus: code.slice(2, 5), version: `${major}.${minor}` });
        return;
    }
    const headerEnd = groupHeaderEnd(group, text);
    items.push({ kind: 'counter', start, end: headerEnd, code: group.code, size: group.count, group_end: end });
    for (const node of group.items) {
        reportNode(node, text, items);
    }
}

/** Where the group's count code ends. signify-ts reports the whole group's span, not the code's. */
function groupHeaderEnd(group: AttachmentGroup, text: Text): number {
    const { start, end } = group.span;
    // Genus 2.00: every group counts its body in quadlets, and the parser ends the group at
    // header end + count * 4, so the header ends that far before the group does. Genus 1.00:
    // signify-ts's Counter, which the parser sized the code with, gives the code's length.
    const headerEnd =
        group.genus === 2
            ? end - group.count * 4
            : start + new Counter({ qb64: text(start, Math.min(start + 8, end)) }).qb64.length;
    const first = group.items[0];
    if (headerEnd <= start || headerEnd > end || (first !== undefined && first.span.start !== headerEnd)) {
        throw new OpError(
            'harness',
            `${E_GROUP_HEADER}: The ${group.code} group signify-ts framed at byte ${start} does not ` +
                `fit its own count code: its header would end at byte ${headerEnd}.`,
        );
    }
    return headerEnd;
}

function reportNode(node: AttachmentNode, text: Text, items: Item[]): void {
    if (node.kind === 'group') {
        reportGroup(node, text, items);
        return;
    }
    items.push(primitive(node, text));
}

function primitive(node: Primitive, text: Text): Item {
    const { start, end } = node.span;
    const qb64 = text(start, end);
    // The parser framed this primitive with the same class; reading it again recovers what the
    // parser's node does not carry (the raw value and indexes).
    const prim = node.class === 'indexer' ? new Indexer({ qb64 }) : new Matter({ qb64 });
    if (prim.code !== node.code) {
        throw new OpError(
            'harness',
            `${E_PRIMITIVE_CODE}: signify-ts framed the primitive at byte ${start} as ${node.code} ` +
                `but reads it back as ${prim.code}.`,
        );
    }
    if (!(prim instanceof Indexer)) {
        return { kind: 'primitive', start, end, code: prim.code, raw: hex(prim.raw) };
    }
    const item: Item = { kind: 'indexed', start, end, code: prim.code, raw: hex(prim.raw), index: prim.index };
    const sizes = Indexer.Sizes.get(prim.code)!;
    if (sizes.os > 0) {
        // signify-ts checks a current-only code's ondex field is zero and then stores none, so for
        // those the field is read back from its own encoding at its own table's offsets.
        const ms = sizes.ss - sizes.os;
        item.ondex = prim.ondex ?? b64ToInt(qb64.slice(sizes.hs + ms, sizes.hs + ms + sizes.os));
    }
    return item;
}

export type MatterMaker = (raw: Uint8Array, code: string) => { qb64: string };
const makeMatter: MatterMaker = (raw, code) => new Matter({ raw, code });

/** Encode one primitive with signify-ts's Matter. signify-ts has no binary domain. */
export function encode(code: string, raw: Uint8Array, domain: string, make: MatterMaker = makeMatter): { encoded: string } {
    if (domain !== 'text') {
        throw new OpError('unsupported', `${E_DOMAIN}: signify-ts encodes only in the text domain (it has no qb2).`);
    }
    let qb64: string;
    try {
        qb64 = make(raw, code).qb64;
    } catch (err) {
        // cesr.encode has no rejection result, so a refusal is answered as unsupported.
        throw new OpError('unsupported', `${E_ENCODE_REFUSED}: signify-ts refused to encode: ${describe(err)}`);
    }
    return { encoded: hex(Buffer.from(qb64, 'latin1')) };
}
