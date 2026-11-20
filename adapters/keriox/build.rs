//! Records which keri-core, cesrox and said this binary was built against, read from Cargo.lock, so that
//! hello reports the resolved versions rather than a constant that could drift from the lock.
//! Every keriox build runs this file against its own Cargo.lock (the keri-core 0.18 build names it
//! in its Cargo.toml), so the table holds the crates of every line the adapter tests.
//! The commit for each version comes from the crate's .cargo_vcs_info.json as published on
//! crates.io; a version without a recorded commit fails the build instead of reporting a guess.

use std::fs;

const COMMITS: &[(&str, &str, &str)] = &[
    (
        "keri-core",
        "0.17.13",
        "b25ba2b1b276706cbe103bc185224071a5e73579",
    ),
    (
        "cesrox",
        "0.1.8",
        "40840948fb669424a0b7629979291ee0c777bb0e",
    ),
    ("said", "0.4.3", "a385e69028fa2d9bd8fda31a9401ad0a630e1361"),
    (
        "keri-core",
        "0.18.0",
        "411f6d4e0591d81e771ae5636ffa8f57ac1a01e3",
    ),
    (
        "cesrox",
        "2.0.0-beta.8",
        "ca35e3efe1cadfcc08fd237e76281b3994524825",
    ),
    ("said", "0.5.4", "86a3f81ca9cdac9535d3405cdd3906d31c89598b"),
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
    for (name, env) in [
        ("keri-core", "KERI_CORE"),
        ("cesrox", "CESROX"),
        ("said", "SAID"),
    ] {
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
