//! The text profile through the binary: stdin, stdout, masks, flags.

use std::io::Write;
use std::process::{Command, Stdio};

fn run(args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_scrump"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn scrump");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn stdin_to_stdout_masks_text_and_default_hits_alike() {
    let input = format!(
        "password: swordfish\nkey AKIA{} here\nplain line\n",
        "Q".repeat(16)
    );
    let (code, out, err) = run(&["--profile", "text", "scrub", "-", "-o", "-"], &input);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        out,
        format!(
            "password: *********\nkey {} here\nplain line\n",
            "*".repeat(20)
        )
    );
    assert!(err.contains("scrubbed"), "status goes to stderr: {err:?}");
    assert!(!out.contains('\0'), "no NUL in text output");
}

#[test]
fn text_profile_does_not_sniff_formats() {
    // `ustar` at byte 257 would make the default dispatcher open a tar.
    let mut input = "password: swordfish\n".to_string();
    while input.len() < 257 {
        input.push_str("filler line of text\n");
    }
    input.truncate(257);
    input.push_str("ustar\nrest of the transcript\n");
    let (code, out, err) = run(&["--profile", "text", "scrub", "-", "-o", "-"], &input);
    assert_eq!(code, 0, "{err}");
    assert!(out.starts_with("password: *********"), "{out:?}");
}

#[test]
fn stream_without_output_is_refused_and_flags_are_validated() {
    let (code, _, err) = run(
        &["--profile", "text", "scrub", "-"],
        "password: swordfish\n",
    );
    assert_ne!(code, 0);
    assert!(err.contains("-o"), "{err}");
    let (code, _, err) = run(&["--mask", "ab", "scrub", "-", "-o", "-"], "x\n");
    assert_ne!(code, 0);
    assert!(err.contains("printable"), "{err}");
    let (code, out, _) = run(
        &["--profile", "text", "--mask", "#", "scrub", "-", "-o", "-"],
        "password: swordfish\n",
    );
    assert_eq!(code, 0);
    assert_eq!(out, "password: #########\n");
    let (code, _, err) = run(
        &[
            "--profile",
            "text",
            "--rules-path",
            "/dev/null",
            "scan",
            "-",
        ],
        "x\n",
    );
    assert_ne!(code, 0);
    assert!(err.contains("cannot be used with"), "{err}");
}
