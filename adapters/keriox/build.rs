//! Records which cesrox and said this binary was built against, read from Cargo.lock, so that
//! hello reports the resolved versions rather than a constant that could drift from the lock.
//! The commit for each version comes from the crate's .cargo_vcs_info.json as published on
//! crates.io; a version without a recorded commit fails the build instead of reporting a guess.

use std::fs;

const COMMITS: &[(&str, &str, &str)] = &[
    (
        "cesrox",
        "0.1.8",
        "40840948fb669424a0b7629979291ee0c777bb0e",
    ),
    ("said", "0.4.3", "a385e69028fa2d9bd8fda31a9401ad0a630e1361"),
];

fn locked_version(lock: &str, name: &str) -> String {
    let mut lines = lock.lines();
    while let Some(line) = lines.next() {
        if line.trim() == format!("name = \"{name}\"") {
            let version = lines
                .next()
                .expect("Cargo.lock entry without a version line");
            let version = version
                .trim()
                .strip_prefix("version = \"")
                .and_then(|v| v.strip_suffix('"'));
            return version
                .expect("Cargo.lock version line is not in the expected form")
                .to_string();
        }
    }
    panic!("Cargo.lock has no entry for {name}");
}

fn main() {
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-changed=build.rs");
    let lock =
        fs::read_to_string("Cargo.lock").expect("Cargo.lock must exist; build with --locked");
    for (name, env) in [("cesrox", "CESROX"), ("said", "SAID")] {
        let version = locked_version(&lock, name);
        let commit = COMMITS
            .iter()
            .find(|(n, v, _)| *n == name && *v == version)
            .map(|(_, _, c)| *c)
            .unwrap_or_else(|| panic!("no commit recorded in build.rs for {name} {version}"));
        println!("cargo:rustc-env=KCS_{env}_VERSION={version}");
        println!("cargo:rustc-env=KCS_{env}_COMMIT={commit}");
    }
}
