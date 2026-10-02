#![no_main]
//! The hook's JSON reader sees whatever the harness sends; errors are fine,
//! panics are not. A string it accepts must survive a round trip.

use libfuzzer_sys::fuzz_target;
use soothsay::json::{parse, Value};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(Value::Str(text)) = parse(s) {
        let again = parse(&soothsay::render::json_str(&text));
        assert_eq!(again, Ok(Value::Str(text)), "json_str/parse round trip");
    }
});
