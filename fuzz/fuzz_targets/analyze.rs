#![no_main]
//! The whole pipeline on arbitrary bytes: lexer, parser, analyzer, and both
//! renderers. None of it may panic, whatever the script contains.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let report = soothsay::analyze_bytes(data);
    let opts = soothsay::render::Options {
        color: true,
        verbose: true,
        source: "fuzz".into(),
    };
    let text = soothsay::render::text(&report, &opts);
    // Script-controlled text must never reach the terminal raw, except our
    // own colour codes.
    let stripped = text.replace("\u{1b}[", "");
    assert!(!stripped.contains('\u{1b}'), "raw ESC in rendered report");
    let _ = soothsay::render::json(&report, "fuzz");
});
