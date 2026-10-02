//! The built binary over real pipes: responses on stdout only, one per line, exit 0 at end of file.

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

#[test]
fn the_binary_answers_over_stdio_and_exits_zero_at_end_of_file() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kcs-adapter-affinidi"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(b"{\"id\":0,\"op\":\"hello\",\"protocol\":1,\"supported\":[1]}\nnot json\n{\"id\":1,\"op\":\"cesr.parse\",\"stream\":\"2d4b\"}\n{\"id\":2,\"op\":\"keri.process\"}\n")
        .unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let lines: Vec<Value> = output
        .stdout
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_slice(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 4, "{lines:?}");
    assert_eq!(lines[0]["result"]["protocol"], 1);
    assert_eq!(lines[1]["id"], Value::Null);
    assert_eq!(lines[2]["id"], 1);
    assert!(
        lines[2]["result"]["reject"]["class"].is_string(),
        "{}",
        lines[2]
    );
    assert_eq!(lines[3]["error"]["kind"], json!("unsupported"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("end of input"), "{stderr}");
}
