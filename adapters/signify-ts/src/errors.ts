// The two error kinds an operation can answer with (adapter protocol, "Messages"), and the codes
// that begin every error message. Every code ends in f: the same request gives the same answer.

export type ErrorKind = 'harness' | 'unsupported';

export class OpError extends Error {
    readonly kind: ErrorKind;

    constructor(kind: ErrorKind, message: string) {
        super(message);
        this.kind = kind;
    }
}

export const E_MALFORMED = 'e.input.format.request.f';
export const E_OVERSIZE = 'e.input.range.request-size.f';
export const E_UNKNOWN_OP = 'e.input.range.unknown-op.f';
export const E_UNDECLARED_OP = 'e.feature.unsupported.undeclared-op.f';
export const E_VERSION = 'e.feature.unsupported.protocol-version.f';
export const E_DOMAIN = 'e.feature.unsupported.domain.f';
export const E_ENCODE_REFUSED = 'e.input.format.encode-refused.f';
export const E_COMMIT = 'e.env.dependency.signify-commit.f';
export const E_EXCEPTION = 'e.self.unknown.exception.f';
export const E_UNCONSUMED = 'e.self.unknown.unconsumed.f';
export const E_GROUP_HEADER = 'e.self.unknown.group-header.f';
export const E_PRIMITIVE_CODE = 'e.self.unknown.primitive-code.f';

/** The text of anything thrown, Error or not. */
export function describe(thrown: unknown): string {
    return thrown instanceof Error ? thrown.message : String(thrown);
}
