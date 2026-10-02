//! hello must report what is actually built: the constants in protocol.rs are checked against
//! Cargo.lock and against the `.cargo_vcs_info.json` crates.io published inside each crate.

use std::path::{Path, PathBuf};

use kcs_adapter_affinidi::protocol;
use serde_json::Value;

fn locked_version(lock: &str, name: &str) -> String {
    let block = lock
        .split("[[package]]")
        .find(|b| b.contains(&format!("name = \"{name}\"\n")))
        .unwrap();
    let line = block.lines().find(|l| l.starts_with("version = ")).unwrap();
    line.trim_start_matches("version = ")
        .trim_matches('"')
        .to_string()
}

#[test]
fn hello_versions_match_cargo_lock() {
    let lock =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock")).unwrap();
    assert_eq!(
        locked_version(&lock, "affinidi-keri-core"),
        protocol::IMPLEMENTATION_VERSION
    );
    assert_eq!(
        locked_version(&lock, "affinidi-cesr"),
        protocol::CESR_CRATE_VERSION
    );
}

/// Every unpacked copy of a published crate in Cargo's registry cache. Cargo unpacks a dependency
/// there before building it, so a built adapter always has at least one.
fn source_dirs(name: &str, version: &str) -> Vec<PathBuf> {
    let home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(&std::env::var_os("HOME").unwrap()).join(".cargo"));
    let mut dirs = Vec::new();
    for index in std::fs::read_dir(home.join("registry").join("src")).unwrap() {
        let dir = index.unwrap().path().join(format!("{name}-{version}"));
        if dir.is_dir() {
            dirs.push(dir);
        }
    }
    assert!(
        !dirs.is_empty(),
        "no unpacked {name}-{version} under {}",
        home.display()
    );
    dirs
}

fn vcs_sha(dir: &Path) -> String {
    let info: Value =
        serde_json::from_slice(&std::fs::read(dir.join(".cargo_vcs_info.json")).unwrap()).unwrap();
    info["git"]["sha1"].as_str().unwrap().to_string()
}

#[test]
fn hello_commits_match_the_published_crates() {
    for dir in source_dirs("affinidi-keri-core", protocol::IMPLEMENTATION_VERSION) {
        assert_eq!(
            vcs_sha(&dir),
            protocol::IMPLEMENTATION_COMMIT,
            "{}",
            dir.display()
        );
    }
    for dir in source_dirs("affinidi-cesr", protocol::CESR_CRATE_VERSION) {
        assert_eq!(
            vcs_sha(&dir),
            protocol::CESR_CRATE_COMMIT,
            "{}",
            dir.display()
        );
    }
}
