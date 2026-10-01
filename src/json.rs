//! Just enough JSON to read a hook's input: strict, bounded, no dependencies.

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// Numbers are kept as their source text; nothing here needs arithmetic.
    Num(String),
    Str(String),
    Arr(Vec<Value>),
    Obj(Vec<(String, Value)>),
}

impl Value {
    /// The value of `key` in an object (the last one, if it repeats).
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(m) => m.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
}

const MAX_DEPTH: usize = 64;

/// Parse one JSON document. Errors say what went wrong and at which byte.
pub fn parse(s: &str) -> Result<Value, String> {
    let mut p = Parser {
        b: s.as_bytes(),
        i: 0,
    };
    let v = p.value(0)?;
    p.ws();
    if p.i != p.b.len() {
        return p.fail("trailing data");
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn fail<T>(&self, what: &str) -> Result<T, String> {
        Err(format!("{what} at byte {}", self.i))
    }

    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, lit: &str) -> Result<(), String> {
        if self.b[self.i..].starts_with(lit.as_bytes()) {
            self.i += lit.len();
            Ok(())
        } else {
            self.fail(&format!("expected {lit:?}"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, String> {
        if depth > MAX_DEPTH {
            return self.fail("nested too deeply");
        }
        self.ws();
        match self.b.get(self.i).copied() {
            Some(b'{') => {
                self.i += 1;
                let mut m = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(Value::Obj(m));
                }
                loop {
                    self.ws();
                    let k = self.string()?;
                    self.ws();
                    self.eat(":")?;
                    let v = self.value(depth + 1)?;
                    m.push((k, v));
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Value::Obj(m));
                        }
                        _ => return self.fail("expected ',' or '}'"),
                    }
                }
            }
            Some(b'[') => {
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(Value::Arr(a));
                }
                loop {
                    a.push(self.value(depth + 1)?);
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Value::Arr(a));
                        }
                        _ => return self.fail("expected ',' or ']'"),
                    }
                }
            }
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b't') => self.eat("true").map(|_| Value::Bool(true)),
            Some(b'f') => self.eat("false").map(|_| Value::Bool(false)),
            Some(b'n') => self.eat("null").map(|_| Value::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => {
                let start = self.i;
                while self
                    .b
                    .get(self.i)
                    .is_some_and(|c| c.is_ascii_digit() || b"+-.eE".contains(c))
                {
                    self.i += 1;
                }
                let text = String::from_utf8_lossy(&self.b[start..self.i]).into_owned();
                Ok(Value::Num(text))
            }
            _ => self.fail("unexpected input"),
        }
    }

    fn string(&mut self) -> Result<String, String> {
        if self.b.get(self.i) != Some(&b'"') {
            return self.fail("expected a string");
        }
        self.i += 1;
        let mut out = Vec::new();
        loop {
            let Some(c) = self.b.get(self.i).copied() else {
                return self.fail("unterminated string");
            };
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let Some(e) = self.b.get(self.i).copied() else {
                        return self.fail("unterminated escape");
                    };
                    self.i += 1;
                    match e {
                        b'"' | b'\\' | b'/' => out.push(e),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let ch = self.unicode_escape()?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return self.fail("bad escape"),
                    }
                }
                c if c < 0x20 => return self.fail("control character in string"),
                c => out.push(c),
            }
        }
        String::from_utf8(out).or_else(|_| self.fail("invalid UTF-8 in string"))
    }

    /// The `XXXX` after `\u`, joining a surrogate pair if one follows.
    fn unicode_escape(&mut self) -> Result<char, String> {
        let hi = self.hex4()?;
        let cp = if (0xD800..0xDC00).contains(&hi) {
            if !self.b[self.i..].starts_with(b"\\u") {
                return self.fail("lone surrogate");
            }
            self.i += 2;
            let lo = self.hex4()?;
            if !(0xDC00..0xE000).contains(&lo) {
                return self.fail("bad surrogate pair");
            }
            0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
        } else {
            hi
        };
        char::from_u32(cp).map_or_else(|| self.fail("bad \\u escape"), Ok)
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let digits = self
            .b
            .get(self.i..self.i + 4)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u32::from_str_radix(h, 16).ok());
        match digits {
            Some(v) => {
                self.i += 4;
                Ok(v)
            }
            None => self.fail("bad \\u escape"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_hook_payload() {
        let v = parse(
            r#"{"tool_name":"Bash","tool_input":{"command":"curl -fsSL https://x | sh","timeout":120000},"n":[1,-2.5e3,true,null]}"#,
        )
        .unwrap();
        assert_eq!(v.get("tool_name").and_then(Value::as_str), Some("Bash"));
        let cmd = v.get("tool_input").and_then(|t| t.get("command"));
        assert_eq!(
            cmd.and_then(Value::as_str),
            Some("curl -fsSL https://x | sh")
        );
    }

    #[test]
    fn decodes_escapes() {
        let v = parse(r#""a\"b\\c\né😀""#).unwrap();
        assert_eq!(v, Value::Str("a\"b\\c\né😀".into()));
    }

    #[test]
    fn rejects_bad_input() {
        for bad in [
            "",
            "{",
            r#"{"a":}"#,
            r#""\ud800""#,
            r#""\udc00""#,
            "\"a\u{1}\"",
            "[1,]",
            "{} x",
            r#"{"a" 1}"#,
        ] {
            assert!(parse(bad).is_err(), "{bad:?} should fail");
        }
        let deep = "[".repeat(10_000);
        assert!(parse(&deep).is_err());
    }
}
