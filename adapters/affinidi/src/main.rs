//! Console entry point: kcs-adapter-affinidi. Requests on stdin, responses on stdout, diagnostics
//! on stderr.

use std::io::{self, BufReader};
use std::process::ExitCode;

fn main() -> ExitCode {
    let stdin = io::stdin();
    let stdout = io::stdout();
    match kcs_adapter_affinidi::protocol::serve(BufReader::new(stdin.lock()), stdout.lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("kcs-adapter-affinidi: e.env.io.stdio.f: {error}");
            ExitCode::FAILURE
        }
    }
}
