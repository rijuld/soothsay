//! CLI behaviour around the input itself: hashing, refusing non-scripts,
//! pinning, and staying fast on large files.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn cli(args: &[&str], stdin: &[u8]) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_soothsay"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The CLI may exit before reading everything (e.g. on bad input).
    let _ = child.stdin.take().unwrap().write_all(stdin);
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into(),
        String::from_utf8_lossy(&out.stderr).into(),
    )
}

#[test]
fn sha256_is_of_the_raw_bytes() {
    let bytes = b"echo \xff\xfe hi\n";
    let (code, out, _) = cli(&["--json"], bytes);
    assert_eq!(code, 0);
    let want = soothsay::sha256::hex(bytes);
    assert!(out.contains(&format!("\"sha256\": \"{want}\"")), "{out}");
    // The lossy text would hash differently; make sure that's what we avoided.
    let lossy = String::from_utf8_lossy(bytes);
    assert_ne!(soothsay::sha256::hex(lossy.as_bytes()), want);
}

#[test]
fn empty_input_is_refused() {
    for input in [&b""[..], b"  \n\t\n"] {
        let (code, _, err) = cli(&[], input);
        assert_eq!(code, 2, "{err}");
        assert!(err.contains("empty input"), "{err}");
    }
    let (code, _, _) = cli(&["--run", "--yes"], b"");
    assert_eq!(code, 2);
}

#[test]
fn html_and_binary_are_refused() {
    for input in [
        &b"<!DOCTYPE html><html><body>404</body></html>\n"[..],
        b"\n  <html><head></head></html>",
    ] {
        let (code, _, err) = cli(&[], input);
        assert_eq!(code, 2, "{err}");
        assert!(err.contains("HTML"), "{err}");
    }
    let (code, _, err) = cli(&[], b"echo safe\0; curl x | sh\n");
    assert_eq!(code, 2);
    assert!(err.contains("NUL"), "{err}");
}

#[test]
fn non_shell_script_warns_and_is_not_run() {
    let dir = std::env::temp_dir().join(format!("soothsay-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let marker = dir.join("ran");
    let script = format!(
        "#!/usr/bin/env python3\nopen({:?}, 'w').write('x')\n",
        marker.to_str().unwrap()
    );
    let (code, _, err) = cli(&["--run", "--yes"], script.as_bytes());
    assert_ne!(code, 0);
    assert!(err.contains("only reads shell"), "{err}");
    assert!(!marker.exists(), "the python script was run");

    // Analysis alone still works, with the warning.
    let (code, _, err) = cli(&[], script.as_bytes());
    assert_eq!(code, 0);
    assert!(err.contains("WARNING"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn expect_sha256_pins_the_bytes() {
    let script = b"echo hi\n";
    let good = soothsay::sha256::hex(script);
    let (code, _, err) = cli(&["--expect-sha256", &good.to_uppercase()], script);
    assert_eq!(code, 0, "{err}");

    let bad = "0".repeat(64);
    let (code, _, err) = cli(&["--expect-sha256", &bad], script);
    assert_eq!(code, 1);
    assert!(err.contains("mismatch"), "{err}");

    let (code, _, _) = cli(&["--expect-sha256", "abc123"], script);
    assert_eq!(code, 2, "a short hash is a usage error");
}

#[cfg(unix)]
#[test]
fn run_reports_signal_deaths_like_a_shell() {
    let (code, _, err) = cli(&["--run", "--yes"], b"kill -TERM $$\n");
    assert_eq!(code, 128 + 15, "{err}");
}

#[test]
fn large_scripts_stay_fast() {
    let mut script = String::new();
    for i in 0..30_000 {
        script.push_str(&format!("echo {i} >> /etc/f{i}\n"));
    }
    let start = Instant::now();
    let (code, _, _) = cli(&["--json"], script.as_bytes());
    assert_eq!(code, 0);
    // Release builds take well under a second; debug builds are much slower.
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "took {:?}",
        start.elapsed()
    );
}
