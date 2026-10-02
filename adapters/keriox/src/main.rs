//! kcs-adapter-keriox: adapter protocol v1 over stdio for keriox's CESR layer.

/// Reading requests from standard input or writing responses to standard output failed, so the
/// session cannot continue. Retrying the same session does not help: the pipe is gone.
pub const E_STDIO: &str = "e.env.io.stdio.f";

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let status = kcs_adapter_keriox::protocol::serve(
        stdin.lock(),
        stdout.lock(),
        kcs_adapter_keriox::protocol::MAX_REQUEST_LINE,
    );
    if let Err(err) = status {
        eprintln!(
            "kcs-adapter-keriox: {E_STDIO}: The adapter could not read a request from standard \
             input or write a response to standard output ({err}), so it is exiting with status \
             1. Check that the runner still holds both ends of the adapter's pipes; a runner \
             that closed standard output early, or was killed, causes this."
        );
        std::process::exit(1);
    }
    eprintln!("kcs-adapter-keriox: end of input, exiting");
}
