//! Randomized "never panics" checks that need no fuzzing toolchain. The
//! generator is a fixed-seed xorshift, so every run tests the same inputs and
//! a failure always reproduces. For open-ended fuzzing, see `fuzz/`.
//!
//! Set `SOOTHSAY_ROBUSTNESS_ITERS` (and optionally `SOOTHSAY_ROBUSTNESS_SEED`)
//! for a longer hunt: `SOOTHSAY_ROBUSTNESS_ITERS=500000 cargo test --release --test robustness`.

use std::time::{Duration, Instant};

/// xorshift64*: tiny, deterministic, good enough to shuffle tokens.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Shell-shaped fragments, weighted toward the syntax the lexer finds hardest.
const SHELL: &[&str] = &[
    "'",
    "\"",
    "`",
    "$(",
    ")",
    "${",
    "}",
    "$((",
    "))",
    "<(",
    ">(",
    "<<",
    "<<-",
    "<<<",
    "EOF",
    "'EOF'",
    "\n",
    "\n",
    " ",
    " ",
    "\t",
    ";",
    ";;",
    "|",
    "||",
    "&&",
    "&",
    "(",
    "[[",
    "]]",
    "{",
    "\\",
    "\\\n",
    "#",
    "=",
    "+=",
    "$",
    "$@",
    "$1",
    "${!x}",
    "${x:-",
    "${#x}",
    "$'\\e[",
    "\\x1b",
    "2>&1",
    ">",
    ">>",
    "&>",
    "<",
    "<>",
    "case",
    "in",
    "esac",
    "for",
    "do",
    "done",
    "if",
    "then",
    "fi",
    "function",
    "f()",
    "eval",
    "exec",
    "sudo",
    "sh",
    "bash",
    "-c",
    "curl",
    "-fsSL",
    "https://x.dev/i.sh",
    "wget",
    "-qO-",
    "base64",
    "-d",
    "source",
    ".",
    "alias",
    "trap",
    "rm",
    "-rf",
    "/",
    "~",
    "~/.zshrc",
    "/etc/sudoers",
    "/dev/tcp/1.2.3.4/80",
    "echo",
    "printf",
    "cat",
    "tee",
    "-a",
    "crontab",
    "-",
    "x",
    "y",
    "é",
    "😀",
    "\u{202e}",
    "\u{0}",
    "\r",
    "*",
    "?",
];

const JSON: &[&str] = &[
    "{", "}", "[", "]", ":", ",", "\"", "\"a\"", "\\", "\\u", "\\ud83d", "\\ude00", "\\n", "0",
    "-1", "1.5e3", "true", "false", "null", " ", "\n", "\u{0}", "é", "x",
];

fn iters(default: usize) -> usize {
    std::env::var("SOOTHSAY_ROBUSTNESS_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn seed(default: u64) -> u64 {
    std::env::var("SOOTHSAY_ROBUSTNESS_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&s| s != 0) // xorshift never leaves 0
        .unwrap_or(default)
}

fn generate(rng: &mut Rng, alphabet: &[&str], max_tokens: usize) -> String {
    let n = rng.below(max_tokens) + 1;
    let mut s = String::new();
    for _ in 0..n {
        s.push_str(alphabet[rng.below(alphabet.len())]);
    }
    s
}

#[test]
fn analyzer_never_panics_on_random_shell() {
    let mut rng = Rng(seed(0x5EED_5007_45A1));
    let n = iters(20_000);
    let start = Instant::now();
    for i in 0..n {
        let src = generate(&mut rng, SHELL, 60);
        let r = std::panic::catch_unwind(|| soothsay::analyze_bytes(src.as_bytes()));
        assert!(r.is_ok(), "case {i} panicked on input: {src:?}");
        let r = std::panic::catch_unwind(|| soothsay::lexer::tokenize(&src));
        assert!(r.is_ok(), "case {i}: lexer panicked on input: {src:?}");
    }
    // Generous enough for a debug build on a slow CI runner.
    assert!(
        start.elapsed() < Duration::from_secs(60) || n > 20_000,
        "{n} random inputs took {:?}",
        start.elapsed()
    );
}

#[test]
fn analyzer_never_panics_on_random_bytes() {
    let mut rng = Rng(seed(0xB17E_5EED));
    for i in 0..iters(20_000) / 4 {
        let n = rng.below(200);
        let bytes: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
        let r = std::panic::catch_unwind(|| soothsay::analyze_bytes(&bytes));
        assert!(r.is_ok(), "case {i} panicked on bytes: {bytes:?}");
    }
}

/// The same invariants the `fuzz/` targets assert, so they're checked on
/// stable too: rendering never panics, and script text never reaches the
/// terminal as a raw escape (only our own `ESC[` colour codes do).
#[test]
fn rendered_reports_never_carry_raw_escapes() {
    let mut rng = Rng(seed(0x0E5C_5EED));
    let opts = soothsay::render::Options {
        color: true,
        verbose: true,
        source: "random".into(),
    };
    for i in 0..iters(20_000) / 4 {
        let src = generate(&mut rng, SHELL, 60);
        let report = soothsay::analyze_bytes(src.as_bytes());
        let text = soothsay::render::text(&report, &opts);
        let stripped = text.replace("\u{1b}[", "");
        assert!(
            !stripped.contains('\u{1b}'),
            "case {i}: raw ESC in the report for input {src:?}"
        );
        let _ = soothsay::render::json(&report, "random");
    }
}

#[test]
fn json_strings_round_trip() {
    let mut rng = Rng(seed(0x7217_5EED));
    for i in 0..iters(20_000) {
        let text = generate(&mut rng, SHELL, 20);
        let encoded = soothsay::render::json_str(&text);
        let back = soothsay::json::parse(&encoded);
        assert_eq!(
            back,
            Ok(soothsay::json::Value::Str(text.clone())),
            "case {i}: {text:?} did not survive json_str -> parse"
        );
    }
}

#[test]
fn json_parser_never_panics() {
    let mut rng = Rng(seed(0x0150_5EED));
    for i in 0..iters(20_000) {
        let src = generate(&mut rng, JSON, 40);
        let r = std::panic::catch_unwind(|| soothsay::json::parse(&src));
        assert!(r.is_ok(), "case {i} panicked on input: {src:?}");
    }
}
