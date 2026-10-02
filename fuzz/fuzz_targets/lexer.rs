#![no_main]
//! The tokenizer alone: it must never panic and never give up.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let src = String::from_utf8_lossy(data);
    let _ = soothsay::lexer::tokenize(&src);
});
