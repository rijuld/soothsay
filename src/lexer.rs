//! A small, forgiving tokenizer for POSIX-ish shell scripts.
//!
//! This is not a full shell parser. It knows enough about quoting, expansions,
//! heredocs and operators to find the *real commands* in an install script, and
//! it never gives up: syntax it doesn't understand degrades into plain words.

/// One piece of a shell word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    /// Literal text, with quotes and escapes already removed.
    Lit(String),
    /// `$NAME`, `${NAME}` or `${NAME:-fallback}`. Forms soothsay can't
    /// evaluate (like `${x%/*}`) keep their raw text in `name`.
    Param {
        name: String,
        fallback: Option<Vec<Part>>,
    },
    /// `$(...)` or backticks: the inner script and the line it starts on.
    Subst { script: String, line: usize },
    /// `<(...)` or `>(...)`.
    ProcSubst { script: String, line: usize },
    /// `$((...))`.
    Arith(String),
}

/// A shell word such as `"$HOME/.bun"/bin`, made of one or more [`Part`]s.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Word {
    pub parts: Vec<Part>,
    /// True if any part of the word was quoted or escaped.
    pub quoted: bool,
}

impl Word {
    /// The word's text, if it is made only of literal parts.
    pub fn literal(&self) -> Option<String> {
        let mut s = String::new();
        for p in &self.parts {
            match p {
                Part::Lit(t) => s.push_str(t),
                _ => return None,
            }
        }
        Some(s)
    }

    /// The word's text if it is literal *and* unquoted, which is how shell
    /// keywords like `if` or `{` must appear to count as keywords.
    pub fn bare(&self) -> Option<String> {
        if self.quoted {
            None
        } else {
            self.literal()
        }
    }
}

/// A redirection such as `>> ~/.zshrc`, `2>&1` or `<<'EOF'`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub fd: Option<u32>,
    pub op: String,
    pub target: Word,
    /// The body of a heredoc (`<<` / `<<-`), once read.
    pub body: Option<String>,
    /// Line the heredoc body starts on.
    pub body_line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Word(Word, usize),
    Op(&'static str, usize),
    Redir(Redirect, usize),
}

/// Split a script into words, operators and redirections.
pub fn tokenize(src: &str) -> Vec<Token> {
    Lexer::new(src, 1).run()
}

const OPERATORS: [&str; 11] = [";;&", ";;", ";&", "&&", "||", "|&", ";", "&", "|", "(", ")"];
const REDIRECTS: [&str; 12] = [
    "&>>", "&>", "<<<", "<<-", "<<", "<>", "<&", ">>", ">|", ">&", "<", ">",
];

struct Lexer {
    s: Vec<char>,
    i: usize,
    line: usize,
    toks: Vec<Token>,
    /// Heredocs waiting for the next newline: (token index, delimiter, strip tabs).
    pending: Vec<(usize, String, bool)>,
    /// Inside `[[ ... ]]`, where `<` and `>` are comparisons, not redirects.
    dbracket: bool,
}

impl Lexer {
    fn new(src: &str, line: usize) -> Self {
        Lexer {
            s: src.chars().collect(),
            i: 0,
            line,
            toks: Vec::new(),
            pending: Vec::new(),
            dbracket: false,
        }
    }

    fn peek(&self) -> Option<char> {
        self.s.get(self.i).copied()
    }

    fn peek_at(&self, n: usize) -> Option<char> {
        self.s.get(self.i + n).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.i += 1;
        if c == '\n' {
            self.line += 1;
        }
        Some(c)
    }

    fn starts_with(&self, pat: &str) -> bool {
        pat.chars()
            .enumerate()
            .all(|(k, c)| self.s.get(self.i + k) == Some(&c))
    }

    fn run(mut self) -> Vec<Token> {
        while let Some(c) = self.peek() {
            match c {
                ' ' | '\t' | '\r' => self.i += 1,
                '\n' => {
                    let l = self.line;
                    self.bump();
                    self.toks.push(Token::Op("\n", l));
                    self.read_heredocs();
                }
                '#' => {
                    while let Some(c) = self.peek() {
                        if c == '\n' {
                            break;
                        }
                        self.i += 1;
                    }
                }
                '\\' if self.peek_at(1) == Some('\n') => {
                    self.bump();
                    self.bump();
                }
                '&' | '|' | '(' | ')' if self.dbracket => {
                    let l = self.line;
                    let op = if self.peek_at(1) == Some(c) && (c == '&' || c == '|') {
                        2
                    } else {
                        1
                    };
                    let text: String = self.s[self.i..self.i + op].iter().collect();
                    self.i += op;
                    self.toks.push(Token::Word(
                        Word {
                            parts: vec![Part::Lit(text)],
                            quoted: false,
                        },
                        l,
                    ));
                }
                '&' if self.peek_at(1) == Some('>') => self.redirect(None),
                ';' | '&' | '|' | '(' | ')' => self.operator(),
                '<' | '>' if self.peek_at(1) == Some('(') => self.word(),
                '<' | '>' if !self.dbracket => self.redirect(None),
                _ => self.word(),
            }
        }
        self.read_heredocs();
        self.toks
    }

    fn operator(&mut self) {
        let l = self.line;
        for op in OPERATORS {
            if self.starts_with(op) {
                self.i += op.chars().count();
                self.toks.push(Token::Op(op, l));
                return;
            }
        }
        self.i += 1;
    }

    fn redirect(&mut self, fd: Option<u32>) {
        let l = self.line;
        let op = REDIRECTS
            .iter()
            .find(|op| self.starts_with(op))
            .copied()
            .unwrap_or(">");
        self.i += op.len();
        while matches!(self.peek(), Some(' ') | Some('\t')) {
            self.i += 1;
        }
        let target = match self.peek() {
            None | Some('\n') | Some(';') | Some('|') | Some('&') | Some(')') => Word::default(),
            _ => self.read_word(),
        };
        let heredoc = op == "<<" || op == "<<-";
        let delim = if heredoc {
            delimiter_text(&target)
        } else {
            String::new()
        };
        self.toks.push(Token::Redir(
            Redirect {
                fd,
                op: op.to_string(),
                target,
                body: None,
                body_line: 0,
            },
            l,
        ));
        if heredoc {
            self.pending.push((self.toks.len() - 1, delim, op == "<<-"));
        }
    }

    fn word(&mut self) {
        let l = self.line;
        let start = self.i;
        let w = self.read_word();
        if self.i == start {
            // Nothing we understand; keep the character so we always make progress.
            let c = self.bump().unwrap_or(' ');
            self.toks.push(Token::Word(
                Word {
                    parts: vec![Part::Lit(c.to_string())],
                    quoted: false,
                },
                l,
            ));
            return;
        }
        if let Some(t) = w.bare() {
            // `2>&1`, `1>/dev/null`: a file descriptor number glued to a redirect.
            let glued_redirect = matches!(self.peek(), Some('<') | Some('>'))
                && self.peek_at(1) != Some('(')
                && !self.dbracket;
            if glued_redirect
                && !t.is_empty()
                && t.len() <= 2
                && t.chars().all(|c| c.is_ascii_digit())
            {
                self.redirect(t.parse().ok());
                return;
            }
            match t.as_str() {
                "[[" => self.dbracket = true,
                "]]" => self.dbracket = false,
                _ => {}
            }
        }
        self.toks.push(Token::Word(w, l));
    }

    fn read_word(&mut self) -> Word {
        let mut w = Word::default();
        let mut lit = String::new();
        while let Some(c) = self.peek() {
            match c {
                ' ' | '\t' | '\r' | '\n' | ';' | '&' | '|' | ')' => break,
                '(' => {
                    // Array assignment: `NAME=(a b c)` stays one word.
                    let name = lit
                        .strip_suffix('=')
                        .map(|n| n.strip_suffix('+').unwrap_or(n));
                    if w.parts.is_empty() && name.is_some_and(is_name) {
                        let inner = self.capture_balanced('(', ')');
                        lit.push('(');
                        lit.push_str(&inner);
                        lit.push(')');
                        continue;
                    }
                    break;
                }
                '<' | '>' => {
                    if self.peek_at(1) == Some('(') && lit.is_empty() && w.parts.is_empty() {
                        let l = self.line;
                        self.i += 1;
                        let script = self.capture_balanced('(', ')');
                        w.parts.push(Part::ProcSubst { script, line: l });
                        continue;
                    }
                    if self.dbracket {
                        lit.push(c);
                        self.i += 1;
                        continue;
                    }
                    break;
                }
                '\\' => {
                    self.i += 1;
                    match self.bump() {
                        Some('\n') | None => {}
                        Some(n) => {
                            lit.push(n);
                            w.quoted = true;
                        }
                    }
                }
                '\'' => {
                    self.i += 1;
                    w.quoted = true;
                    while let Some(n) = self.bump() {
                        if n == '\'' {
                            break;
                        }
                        lit.push(n);
                    }
                }
                '"' => {
                    self.i += 1;
                    w.quoted = true;
                    self.read_dquoted(&mut w, &mut lit, Some('"'));
                }
                '`' => {
                    self.i += 1;
                    flush(&mut w, &mut lit);
                    let l = self.line;
                    let script = self.read_backtick();
                    w.parts.push(Part::Subst { script, line: l });
                }
                '$' => self.dollar(&mut w, &mut lit, false),
                _ => {
                    lit.push(c);
                    self.i += 1;
                }
            }
        }
        flush(&mut w, &mut lit);
        w
    }

    /// Contents of a double-quoted string (or of a `${x:-...}` fallback when
    /// `end` is `None`).
    fn read_dquoted(&mut self, w: &mut Word, lit: &mut String, end: Option<char>) {
        while let Some(c) = self.peek() {
            if Some(c) == end {
                self.i += 1;
                return;
            }
            match c {
                '\\' => {
                    self.i += 1;
                    match self.bump() {
                        Some('\n') | None => {}
                        Some(n) if "$`\"\\".contains(n) => lit.push(n),
                        Some(n) => {
                            lit.push('\\');
                            lit.push(n);
                        }
                    }
                }
                '$' => self.dollar(w, lit, true),
                '`' => {
                    self.i += 1;
                    flush(w, lit);
                    let l = self.line;
                    let script = self.read_backtick();
                    w.parts.push(Part::Subst { script, line: l });
                }
                '"' if end.is_none() => self.i += 1,
                '\'' if end.is_none() => {
                    self.i += 1;
                    while let Some(n) = self.bump() {
                        if n == '\'' {
                            break;
                        }
                        lit.push(n);
                    }
                }
                _ => {
                    self.bump();
                    lit.push(c);
                }
            }
        }
    }

    fn dollar(&mut self, w: &mut Word, lit: &mut String, in_dquote: bool) {
        self.i += 1; // the '$'
        match self.peek() {
            Some('(') => {
                flush(w, lit);
                let l = self.line;
                if self.peek_at(1) == Some('(') {
                    let inner = self.capture_balanced('(', ')');
                    let inner = inner.strip_prefix('(').unwrap_or(&inner);
                    let inner = inner.strip_suffix(')').unwrap_or(inner);
                    w.parts.push(Part::Arith(inner.trim().to_string()));
                } else {
                    let script = self.capture_balanced('(', ')');
                    w.parts.push(Part::Subst { script, line: l });
                }
            }
            Some('{') => {
                flush(w, lit);
                let l = self.line;
                let inner = self.capture_balanced('{', '}');
                w.parts.push(parse_param(&inner, l));
            }
            Some('\'') if !in_dquote => {
                self.i += 1;
                w.quoted = true;
                self.read_ansi_c(lit);
            }
            Some('"') if !in_dquote => {
                self.i += 1;
                w.quoted = true;
                self.read_dquoted(w, lit, Some('"'));
            }
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {
                flush(w, lit);
                let mut name = String::new();
                while let Some(c) = self.peek() {
                    if c.is_ascii_alphanumeric() || c == '_' {
                        name.push(c);
                        self.i += 1;
                    } else {
                        break;
                    }
                }
                w.parts.push(Part::Param {
                    name,
                    fallback: None,
                });
            }
            Some(c) if c.is_ascii_digit() || "?#@*$!-".contains(c) => {
                flush(w, lit);
                self.i += 1;
                w.parts.push(Part::Param {
                    name: c.to_string(),
                    fallback: None,
                });
            }
            _ => lit.push('$'),
        }
    }

    /// `$'...'` strings, with the common C escapes decoded.
    fn read_ansi_c(&mut self, lit: &mut String) {
        while let Some(c) = self.bump() {
            match c {
                '\'' => return,
                '\\' => match self.bump() {
                    Some('n') => lit.push('\n'),
                    Some('t') => lit.push('\t'),
                    Some('r') => lit.push('\r'),
                    Some('e') | Some('E') => lit.push('\u{1b}'),
                    Some('x') => {
                        let mut hex = String::new();
                        while hex.len() < 2 && self.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
                            hex.push(self.bump().unwrap_or('0'));
                        }
                        if let Some(ch) =
                            u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)
                        {
                            lit.push(ch);
                        }
                    }
                    Some(n) => lit.push(n),
                    None => return,
                },
                _ => lit.push(c),
            }
        }
    }

    fn read_backtick(&mut self) -> String {
        let mut out = String::new();
        while let Some(c) = self.bump() {
            match c {
                '`' => break,
                '\\' => match self.bump() {
                    Some('`') => out.push('`'),
                    Some(n) => {
                        out.push('\\');
                        out.push(n);
                    }
                    None => break,
                },
                _ => out.push(c),
            }
        }
        out
    }

    /// Consume from an opening delimiter to its match and return what's inside,
    /// skipping over quoted strings so `$(echo ")")` works.
    fn capture_balanced(&mut self, open: char, close: char) -> String {
        let mut out = String::new();
        let mut depth = 0usize;
        while let Some(c) = self.bump() {
            match c {
                c if c == open => {
                    depth += 1;
                    if depth == 1 {
                        continue;
                    }
                }
                c if c == close => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return out;
                    }
                }
                '\\' => {
                    out.push(c);
                    if let Some(n) = self.bump() {
                        out.push(n);
                    }
                    continue;
                }
                '\'' | '"' => {
                    out.push(c);
                    while let Some(n) = self.bump() {
                        out.push(n);
                        if n == '\\' && c == '"' {
                            if let Some(m) = self.bump() {
                                out.push(m);
                            }
                            continue;
                        }
                        if n == c {
                            break;
                        }
                    }
                    continue;
                }
                _ => {}
            }
            out.push(c);
        }
        out
    }

    fn read_heredocs(&mut self) {
        for (idx, delim, strip) in std::mem::take(&mut self.pending) {
            let body_line = self.line;
            let mut body = String::new();
            while self.i < self.s.len() {
                let mut line = String::new();
                while let Some(c) = self.peek() {
                    self.i += 1;
                    if c == '\n' {
                        self.line += 1;
                        break;
                    }
                    line.push(c);
                }
                let text = if strip {
                    line.trim_start_matches('\t')
                } else {
                    line.as_str()
                };
                if text.trim_end_matches('\r') == delim {
                    break;
                }
                body.push_str(text);
                body.push('\n');
            }
            if let Some(Token::Redir(r, _)) = self.toks.get_mut(idx) {
                r.body = Some(body);
                r.body_line = body_line;
            }
        }
    }
}

fn flush(w: &mut Word, lit: &mut String) {
    if !lit.is_empty() {
        w.parts.push(Part::Lit(std::mem::take(lit)));
    }
}

pub(crate) fn is_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn delimiter_text(w: &Word) -> String {
    let mut s = String::new();
    for p in &w.parts {
        match p {
            Part::Lit(t) => s.push_str(t),
            Part::Param { name, .. } => {
                s.push('$');
                s.push_str(name);
            }
            _ => {}
        }
    }
    s
}

/// Interpret the inside of `${...}`.
fn parse_param(inner: &str, line: usize) -> Part {
    // `${!ref:-default}` is indirect: the name can't be resolved, the fallback can.
    if let Some(rest) = inner.strip_prefix('!') {
        if let Part::Param {
            name,
            fallback: Some(fb),
        } = parse_param(rest, line)
        {
            return Part::Param {
                name: format!("!{name}"),
                fallback: Some(fb),
            };
        }
        return Part::Param {
            name: inner.to_string(),
            fallback: None,
        };
    }
    let name_len = inner
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .count();
    if name_len == 0 {
        return Part::Param {
            name: inner.to_string(),
            fallback: None,
        };
    }
    let (name, rest) = inner.split_at(name_len);
    if rest.is_empty() {
        return Part::Param {
            name: name.to_string(),
            fallback: None,
        };
    }
    for op in [":-", ":=", "-", "="] {
        if let Some(default) = rest.strip_prefix(op) {
            let mut lx = Lexer::new(default, line);
            let mut w = Word::default();
            let mut lit = String::new();
            lx.read_dquoted(&mut w, &mut lit, None);
            flush(&mut w, &mut lit);
            return Part::Param {
                name: name.to_string(),
                fallback: Some(w.parts),
            };
        }
    }
    Part::Param {
        name: inner.to_string(),
        fallback: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(src: &str) -> Vec<String> {
        tokenize(src)
            .into_iter()
            .filter_map(|t| match t {
                Token::Word(w, _) => Some(w.literal().unwrap_or_else(|| "<dyn>".into())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn quotes_and_escapes() {
        assert_eq!(
            words(r#"echo 'a b' "c d" e\ f"#),
            ["echo", "a b", "c d", "e f"]
        );
    }

    #[test]
    fn comments_only_at_word_start() {
        assert_eq!(words("echo a#b # real comment"), ["echo", "a#b"]);
        assert_eq!(words(r#"echo "x # y""#), ["echo", "x # y"]);
        let t = tokenize("echo ${#x}");
        assert!(
            matches!(&t[1], Token::Word(w, _) if matches!(&w.parts[0], Part::Param { name, .. } if name == "#x"))
        );
    }

    #[test]
    fn command_substitution_nests() {
        let t = tokenize(r#"sh -c "$(curl -fsSL "https://x.dev/a)b")""#);
        let Token::Word(w, _) = &t[2] else { panic!() };
        let Part::Subst { script, .. } = &w.parts[0] else {
            panic!("{w:?}")
        };
        assert_eq!(script, r#"curl -fsSL "https://x.dev/a)b""#);
    }

    #[test]
    fn heredoc_bodies_are_not_commands() {
        let t = tokenize("cat > f <<'EOF'\nrm -rf /\nEOF\necho done\n");
        let bodies: Vec<_> = t
            .iter()
            .filter_map(|t| match t {
                Token::Redir(r, _) => r.body.clone(),
                _ => None,
            })
            .collect();
        assert_eq!(bodies, ["rm -rf /\n"]);
        assert_eq!(
            words("cat > f <<'EOF'\nrm -rf /\nEOF\necho done\n"),
            ["cat", "echo", "done"]
        );
    }

    #[test]
    fn fd_redirects() {
        let t = tokenize("cmd 2>&1 >/dev/null");
        let ops: Vec<_> = t
            .iter()
            .filter_map(|t| match t {
                Token::Redir(r, _) => Some((r.fd, r.op.clone(), r.target.literal().unwrap())),
                _ => None,
            })
            .collect();
        assert_eq!(
            ops,
            [
                (Some(2), ">&".into(), "1".into()),
                (None, ">".into(), "/dev/null".into())
            ]
        );
    }

    #[test]
    fn param_fallback() {
        let t = tokenize(r#"echo "${BUN_INSTALL:-$HOME/.bun}""#);
        let Token::Word(w, _) = &t[1] else { panic!() };
        let Part::Param {
            name,
            fallback: Some(fb),
        } = &w.parts[0]
        else {
            panic!("{w:?}")
        };
        assert_eq!(name, "BUN_INSTALL");
        assert_eq!(
            fb[0],
            Part::Param {
                name: "HOME".into(),
                fallback: None
            }
        );
    }

    #[test]
    fn ansi_c_strings() {
        assert_eq!(words(r"printf $'a\x41\n'"), ["printf", "aA\n"]);
    }

    #[test]
    fn array_assignment_is_one_word() {
        assert_eq!(words("PKGS=(curl git) ; x"), ["PKGS=(curl git)", "x"]);
        assert_eq!(words("PKGS+=(\n  a\n) ; x"), ["PKGS+=(\n  a\n)", "x"]);
    }

    #[test]
    fn double_bracket_operators_stay_inside_the_test() {
        assert_eq!(
            words("[[ $# = 2 && $2 = x ]] && y"),
            ["[[", "<dyn>", "=", "2", "&&", "<dyn>", "=", "x", "]]", "y"]
        );
    }

    #[test]
    fn indirect_expansion_keeps_fallback() {
        let t = tokenize("echo ${!env:-$HOME/.bun}");
        let Token::Word(w, _) = &t[1] else { panic!() };
        assert!(matches!(&w.parts[0], Part::Param { name, fallback: Some(_) } if name == "!env"));
    }
}
