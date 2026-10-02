//! Console entry point: kcs-adapter-affinidi. Requests on stdin, responses on stdout, diagnostics
//! on stderr.

use std::io::{self, BufReader};
use std::process::ExitCode;

/// Standard input or output failed, so the session cannot continue.
const E_STDIO: &str = "e.env.io.stdio.f";

fn main() -> ExitCode {
    let stdin = io::stdin();
    let stdout = io::stdout();
    match kcs_adapter_affinidi::protocol::serve(BufReader::new(stdin.lock()), stdout.lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "kcs-adapter-affinidi: {E_STDIO}: The adapter stopped because reading a request \
                 from standard input or writing a response to standard output failed: {error}."
            );
            ExitCode::FAILURE
        }
    }
}
