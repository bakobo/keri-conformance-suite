//! kcs-adapter-keriox: adapter protocol v1 over stdio for keriox's CESR layer.

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let status = kcs_adapter_keriox::protocol::serve(
        stdin.lock(),
        stdout.lock(),
        kcs_adapter_keriox::protocol::MAX_REQUEST_LINE,
    );
    eprintln!("kcs-adapter-keriox: end of input, exiting");
    if let Err(err) = status {
        eprintln!("kcs-adapter-keriox: I/O error: {err}");
        std::process::exit(1);
    }
}
