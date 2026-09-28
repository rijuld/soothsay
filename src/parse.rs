//! Turns tokens into a flat list of simple commands, remembering which
//! pipeline each belongs to and which function (if any) encloses it.

use crate::lexer::{tokenize, Redirect, Token, Word};

/// One simple command, e.g. `sudo mv "$tmp/bin" /usr/local/bin >/dev/null`.
#[derive(Debug, Clone)]
pub struct Command {
    pub words: Vec<Word>,
    pub redirects: Vec<Redirect>,
    /// 1-based line in the original script.
    pub line: usize,
    /// Add this to a line number produced by the lexer for this command's
    /// source (e.g. the line of a `$(...)` part) to get the real line.
    pub offset: usize,
    /// Enclosing function, if any.
    pub function: Option<String>,
    /// Commands in the same pipeline share this id; `stage` is their position.
    pub pipeline: usize,
    pub stage: usize,
}

#[derive(Debug, Default)]
pub struct Script {
    pub commands: Vec<Command>,
    /// Functions defined in this script, with the line they start on.
    pub functions: Vec<(String, usize)>,
}

#[derive(Clone, Copy)]
enum Case {
    Header,
    Pattern,
    Body,
}

/// Parse `src`, whose first line is line `offset + 1` of the original script.
/// Commands are attributed to `function` unless they sit in a nested function.
pub fn parse(src: &str, offset: usize, function: Option<String>) -> Script {
    let toks = tokenize(src);
    let mut p = Parser {
        script: Script::default(),
        words: Vec::new(),
        redirs: Vec::new(),
        line: 0,
        pipeline: 0,
        stage: 0,
        scopes: vec![function],
        cases: Vec::new(),
        pending_func: None,
        expect_fn_name: false,
        skip_to_sep: false,
        offset,
    };
    let mut i = 0;
    while i < toks.len() {
        match &toks[i] {
            Token::Word(w, l) => p.word(w, *l),
            Token::Redir(r, l) => {
                if !p.skip_to_sep && !matches!(p.cases.last(), Some(Case::Header | Case::Pattern)) {
                    if p.words.is_empty() && p.redirs.is_empty() {
                        p.line = *l;
                    }
                    p.redirs.push(r.clone());
                }
            }
            Token::Op(op, l) => {
                let in_body = matches!(p.cases.last(), None | Some(Case::Body));
                if *op == "(" && in_body && matches!(toks.get(i + 1), Some(Token::Op(")", _))) {
                    // `name() { ... }`
                    if p.words.len() == 1 {
                        if let Some(name) = p.words[0].bare() {
                            p.words.clear();
                            p.define(name, *l);
                            i += 2;
                            continue;
                        }
                    }
                    // `function name() { ... }`
                    if p.words.is_empty() && p.pending_func.is_some() {
                        i += 2;
                        continue;
                    }
                }
                p.op(op);
            }
        }
        i += 1;
    }
    p.finish();
    p.script
}

struct Parser {
    script: Script,
    words: Vec<Word>,
    redirs: Vec<Redirect>,
    line: usize,
    pipeline: usize,
    stage: usize,
    /// Brace groups / subshells, each remembering its enclosing function.
    scopes: Vec<Option<String>>,
    cases: Vec<Case>,
    pending_func: Option<String>,
    expect_fn_name: bool,
    skip_to_sep: bool,
    offset: usize,
}

impl Parser {
    fn current_func(&self) -> Option<String> {
        self.scopes.last().cloned().flatten()
    }

    fn define(&mut self, name: String, line: usize) {
        self.script
            .functions
            .push((name.clone(), line + self.offset));
        self.pending_func = Some(name);
    }

    fn open_scope(&mut self) {
        let f = self.pending_func.take().or_else(|| self.current_func());
        self.scopes.push(f);
    }

    fn close_scope(&mut self) {
        if self.scopes.len() > 1 {
            self.scopes.pop();
        }
    }

    fn word(&mut self, w: &Word, l: usize) {
        if self.skip_to_sep {
            return;
        }
        let bare = w.bare();
        let kw = bare.as_deref();
        if let Some(state) = self.cases.last().copied() {
            match state {
                Case::Header => {
                    if kw == Some("in") {
                        *self.cases.last_mut().unwrap() = Case::Pattern;
                    }
                    return;
                }
                Case::Pattern => {
                    if kw == Some("esac") {
                        self.cases.pop();
                    }
                    return;
                }
                Case::Body => {
                    if self.words.is_empty() && kw == Some("esac") {
                        self.cases.pop();
                        return;
                    }
                }
            }
        }
        if self.words.is_empty() {
            if self.expect_fn_name {
                if let Some(name) = bare {
                    self.expect_fn_name = false;
                    self.define(name, l);
                    return;
                }
            }
            match kw {
                Some("{") => return self.open_scope(),
                Some("}") => return self.close_scope(),
                Some(
                    "if" | "then" | "elif" | "else" | "fi" | "do" | "done" | "while" | "until"
                    | "!" | "time",
                ) => return,
                Some("for" | "select") => {
                    self.skip_to_sep = true;
                    return;
                }
                Some("case") => {
                    self.cases.push(Case::Header);
                    return;
                }
                Some("function") => {
                    self.expect_fn_name = true;
                    return;
                }
                _ => {}
            }
            if self.redirs.is_empty() {
                self.line = l;
            }
        }
        self.words.push(w.clone());
    }

    fn op(&mut self, op: &str) {
        if let Some(state) = self.cases.last().copied() {
            match state {
                Case::Header => return,
                Case::Pattern => {
                    if op == ")" {
                        *self.cases.last_mut().unwrap() = Case::Body;
                    }
                    return;
                }
                Case::Body => {
                    if matches!(op, ";;" | ";&" | ";;&") {
                        self.finish();
                        self.new_pipeline();
                        *self.cases.last_mut().unwrap() = Case::Pattern;
                        return;
                    }
                }
            }
        }
        match op {
            "|" | "|&" => {
                self.finish();
                self.stage += 1;
            }
            "(" => {
                self.finish();
                self.open_scope();
            }
            ")" => {
                self.finish();
                self.close_scope();
            }
            _ => {
                self.finish();
                self.new_pipeline();
            }
        }
    }

    fn new_pipeline(&mut self) {
        self.skip_to_sep = false;
        self.pipeline += 1;
        self.stage = 0;
    }

    fn finish(&mut self) {
        if self.words.is_empty() && self.redirs.is_empty() {
            return;
        }
        self.script.commands.push(Command {
            words: std::mem::take(&mut self.words),
            redirects: std::mem::take(&mut self.redirs),
            line: self.line + self.offset,
            offset: self.offset,
            function: self.current_func(),
            pipeline: self.pipeline,
            stage: self.stage,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn heads(src: &str) -> Vec<(String, Option<String>, usize)> {
        parse(src, 0, None)
            .commands
            .iter()
            .map(|c| {
                (
                    c.words[0].literal().unwrap_or_default(),
                    c.function.clone(),
                    c.stage,
                )
            })
            .collect()
    }

    #[test]
    fn functions_and_pipelines() {
        let src =
            "install() {\n  curl -fsSL x | tar xz\n}\nfunction other { rm -rf y; }\ninstall\n";
        assert_eq!(
            heads(src),
            [
                ("curl".into(), Some("install".into()), 0),
                ("tar".into(), Some("install".into()), 1),
                ("rm".into(), Some("other".into()), 0),
                ("install".into(), None, 0),
            ]
        );
    }

    #[test]
    fn case_patterns_are_not_commands() {
        let src = "case \"$os\" in\n  Darwin|darwin) arch=mac ;;\n  *) echo other ;;\nesac\nnext\n";
        let h: Vec<_> = heads(src).into_iter().map(|h| h.0).collect();
        assert_eq!(h, ["arch=mac", "echo", "next"]);
    }

    #[test]
    fn keywords_are_skipped() {
        let src = "if ! command -v git >/dev/null; then\n  sudo apt install git\nfi\nfor f in a b; do rm \"$f\"; done\n";
        let h: Vec<_> = heads(src).into_iter().map(|h| h.0).collect();
        assert_eq!(h, ["command", "sudo", "rm"]);
    }
}
