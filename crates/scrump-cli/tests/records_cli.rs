//! `--records`: records separated by 0x1E, each scanned on its own.
//!
//! Secret-shaped vectors are built from pieces at run time, so this file
//! carries nothing a secret scanner would flag.

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

fn scrub(args: &[&str], input: &str) -> String {
    let mut all = vec!["--profile", "text"];
    all.extend_from_slice(args);
    all.extend_from_slice(&["scrub", "-", "-o", "-"]);
    let (code, out, err) = run(&all, input);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.len(), input.len(), "masks keep the length");
    out
}

/// The canary tacit's redaction check uses, in pieces.
fn canary() -> String {
    ["Zq7", "Vx9", "Lm2", "Kp4"].concat()
}

/// A password in the next record: `password: '<canary>' and the rest`.
fn password_record() -> String {
    format!("{}: '{}' and the rest", ["pass", "word"].concat(), canary())
}

/// The ways a hit that starts in one record runs into the next when the
/// records are scanned as one stream.
fn crossing_shapes() -> Vec<(&'static str, String, String)> {
    vec![
        (
            // tacit#84: a setting's quoted value a cut left open runs to the
            // next quote; the filter keeps the setting, masks nothing, and the
            // scan resumes past the next record's key.
            "a filtered setting left open (the issue's repro)",
            format!(
                "deploy token_url: 'https://auth.example.invalid/oauth/{}",
                "p".repeat(80)
            ),
            password_record(),
        ),
        (
            // A reference to a vault is not a secret: filtered the same way.
            "a filtered reference left open",
            format!(
                "DB_{}='$(vault read -field=value secret/db/{}",
                ["PASS", "WORD"].concat(),
                "q".repeat(80)
            ),
            password_record(),
        ),
        (
            // A credential's value left open is masked up to the next
            // record's opening quote, and the scan resumes inside it.
            "an open quote",
            format!("api_key: '{}{} cut here", "Wq8Ux0", "Kn3Jp5"),
            password_record(),
        ),
        (
            // A keyword rule reaches across lines: the keyword at the end of
            // one record takes a token at the start of the next.
            "a keyword rule's reach",
            "notes on the abstract".to_string(),
            format!(
                "{} is the build id",
                "a1b2c3d4e5f6a7b8c9d0".to_owned() + "e1f2a3b4c5d6"
            ),
        ),
    ]
}

#[test]
fn each_record_is_masked_as_it_is_alone() {
    for (name, first, second) in crossing_shapes() {
        let alone = [scrub(&[], &first), scrub(&[], &second)];
        // The vector crosses: in one stream the second record does not come
        // back as it does alone.
        let stream = scrub(&[], &format!("{first}\n\x1e\n{second}"));
        assert_ne!(
            stream.split("\n\x1e\n").nth(1),
            Some(alone[1].as_str()),
            "{name}: the vector no longer crosses records in one stream"
        );
        let records = scrub(&["--records"], &format!("{first}\x1e{second}"));
        let got: Vec<&str> = records.split('\x1e').collect();
        assert_eq!(got, alone, "{name}");
    }
    // The password the stream would have kept is masked.
    let records = scrub(
        &["--records"],
        &format!(
            "deploy token_url: 'https://auth.example.invalid/oauth/{}\x1e{}",
            "p".repeat(80),
            password_record()
        ),
    );
    assert!(!records.contains(&canary()), "{records:?}");
    assert!(
        records.ends_with("'************' and the rest"),
        "{records:?}"
    );
}

#[test]
fn records_keep_their_separators_and_places() {
    let secret = format!("{}={}", ["pass", "word"].concat(), canary());
    let input = format!("\x1e{secret}\x1e\x1eplain text\x1e{secret}\x1e");
    let out = scrub(&["--records"], &input);
    let at = |s: &str| -> Vec<usize> { s.match_indices('\x1e').map(|(i, _)| i).collect() };
    assert_eq!(at(&out), at(&input));
    let parts: Vec<&str> = out.split('\x1e').collect();
    assert_eq!(parts.len(), 6);
    assert_eq!(parts[1], "password=************");
    assert_eq!(parts[3], "plain text");
    assert_eq!(parts[4], "password=************");
    // Input without a separator is one record, masked as in one stream.
    assert_eq!(scrub(&["--records"], &secret), scrub(&[], &secret));
}

#[test]
fn scan_names_the_record_of_each_hit() {
    let input = format!("clean\x1e{}={}", ["pass", "word"].concat(), canary());
    let (code, out, err) = run(&["--profile", "text", "--records", "scan", "-"], &input);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("(format=records)"), "{out}");
    assert!(out.contains("origin=Section(\"record 1\")"), "{out}");
    assert!(!out.contains("record 0"), "{out}");
}

#[test]
fn records_are_text_and_take_no_format() {
    // Records are never sniffed, under the default profile too: `ustar` at
    // byte 257 would open a tar.
    let mut first = "x".repeat(257);
    first.push_str("ustar");
    let key = format!("AKIA{}", "Q".repeat(16));
    let input = format!("{first}\x1ekey {key} here");
    let (code, out, err) = run(&["--records", "scrub", "-", "-o", "-"], &input);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("(format=records)"), "{err}");
    assert!(out.starts_with(&first), "{out:?}");
    assert!(!out.contains(&key), "{out:?}");
    let (code, _, err) = run(&["--records", "--format", "tar", "scan", "-"], "x");
    assert_ne!(code, 0);
    assert!(err.contains("cannot be used with"), "{err}");
}
