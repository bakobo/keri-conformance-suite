// The two error kinds an operation can answer with (adapter protocol, "Messages"), and the codes
// that begin every error message. A code ending in f means the same request gives the same answer;
// one ending in t means KERIA or Docker failed, and trying again may help.

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
export const E_COMMIT = 'e.env.dependency.signify-commit.f';
export const E_KERIA_START = 'e.env.dependency.keria-start.t';
export const E_KERIA = 'e.env.dependency.keria.t';
export const E_EXCEPTION = 'e.self.unknown.exception.f';

/** The text of anything thrown, Error or not. */
export function describe(thrown: unknown): string {
    return thrown instanceof Error ? thrown.message : String(thrown);
}
