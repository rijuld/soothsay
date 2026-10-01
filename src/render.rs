//! Human and machine output.

use std::fmt::Write as _;

use crate::analyze::{shorten, Category, Finding, Report, Severity, Touch};

pub struct Options {
    pub color: bool,
    /// Show info-level findings and uncapped lists.
    pub verbose: bool,
    /// Name shown in the header (file name or "stdin").
    pub source: String,
}

struct Paint(bool);

impl Paint {
    fn wrap(&self, code: &str, s: &str) -> String {
        if self.0 {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }
    fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }
    fn sev(&self, sev: Severity, s: &str) -> String {
        let code = match sev {
            Severity::Danger => "1;31",
            Severity::Warn => "1;33",
            Severity::Notice => "36",
            Severity::Info => "2",
        };
        self.wrap(code, s)
    }
}

fn icon(sev: Severity) -> &'static str {
    match sev {
        Severity::Danger => "✖",
        Severity::Warn => "▲",
        Severity::Notice => "●",
        Severity::Info => "·",
    }
}

pub fn verdict(max: Option<Severity>) -> (&'static str, &'static str) {
    match max {
        None | Some(Severity::Info) => (
            "✨",
            "Clear skies. Nothing beyond ordinary installer chores.",
        ),
        Some(Severity::Notice) => (
            "🌤 ",
            "Mild omens. Typical installer behaviour; skim the notices.",
        ),
        Some(Severity::Warn) => ("🌩 ", "Storm clouds. Read the warnings before you run this."),
        Some(Severity::Danger) => (
            "☠️ ",
            "Dark omens. Don't run this unless you understand every red line.",
        ),
    }
}

const CAP: usize = 8;

/// Make script-derived text safe to print on a terminal.
///
/// The script decides what goes into paths, URLs and snippets, so it could
/// otherwise embed escape sequences that hide lines, move the cursor or
/// reorder text. Control, bidi and zero-width characters are shown as
/// visible escapes instead; a newline becomes `⏎`.
pub fn clean(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push_str(" ⏎ "),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\u{1b}' => out.push_str("\\x1b"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            '\u{80}'..='\u{9f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
            | '\u{200b}'..='\u{200f}'
            | '\u{061c}'
            | '\u{2060}'
            | '\u{feff}' => {
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

pub fn text(r: &Report, o: &Options) -> String {
    let p = Paint(o.color);
    let mut out = String::new();
    let short_hash = format!("{}…{}", &r.sha256[..8], &r.sha256[r.sha256.len() - 4..]);
    let _ = writeln!(
        out,
        "\n🔮 {}  {}",
        p.bold("soothsay"),
        p.dim(&format!(
            "{} · {} lines · {} · sha256 {}",
            clean(&o.source),
            r.lines,
            clean(&r.interpreter),
            short_hash
        ))
    );

    let mut shown_any = false;
    // Hidden because they're low-level, vs. hidden because they sit in a
    // function soothsay thinks is never called. The second kind can be a
    // script hiding from the reader, so it's never called "low-level".
    let mut hidden_info = 0usize;
    let mut hidden_unreachable = 0usize;
    for cat in Category::ALL {
        let mut items: Vec<&Finding> = r
            .findings
            .iter()
            .filter(|f| {
                f.category == cat && (o.verbose || (f.severity > Severity::Info && f.reachable))
            })
            .collect();
        if !o.verbose {
            for f in r.findings.iter().filter(|f| f.category == cat) {
                if !f.reachable {
                    hidden_unreachable += 1;
                } else if f.severity == Severity::Info {
                    hidden_info += 1;
                }
            }
        }
        if items.is_empty() {
            continue;
        }
        items.sort_by_key(|f| {
            (
                std::cmp::Reverse(f.reachable),
                std::cmp::Reverse(f.severity),
                f.line,
            )
        });
        // The same thing on several lines is one entry: "L177 (also L197, L229)".
        let mut grouped: Vec<(&Finding, Vec<usize>)> = Vec::new();
        for f in items.iter().copied() {
            let same = grouped.iter_mut().find(|(g, _)| {
                g.message == f.message
                    && g.detail == f.detail
                    && g.reachable == f.reachable
                    && g.severity == f.severity
            });
            match same {
                Some((_, lines)) => lines.push(f.line),
                None => grouped.push((f, Vec::new())),
            }
        }
        let top = items
            .iter()
            .filter(|f| f.reachable)
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info);
        shown_any = true;
        let _ = writeln!(
            out,
            "\n  {} {}",
            p.sev(top, icon(top)),
            p.sev(top, &cat.title().to_uppercase())
        );
        let limit = if o.verbose { usize::MAX } else { CAP };
        for (f, also) in grouped.iter().take(limit) {
            let loc = format!("L{:<5}", f.line);
            let mut msg = clean(&f.message);
            if !also.is_empty() {
                let lines: Vec<String> = also.iter().take(6).map(|l| format!("L{l}")).collect();
                let more = if also.len() > 6 { ", …" } else { "" };
                msg = format!(
                    "{msg} {}",
                    p.dim(&format!("(also {}{more})", lines.join(", ")))
                );
            }
            if !f.reachable {
                msg = p.dim(&format!(
                    "{msg}  (in {}(), which is never called)",
                    clean(f.function.as_deref().unwrap_or("?"))
                ));
            } else {
                msg = p.sev(f.severity, icon(f.severity)) + " " + &msg;
            }
            let _ = writeln!(out, "    {} {}", p.dim(&loc), msg);
            if let Some(d) = &f.detail {
                let _ = writeln!(out, "           {}", p.dim(&format!("↳ {}", clean(d))));
            }
        }
        if grouped.len() > limit {
            let _ = writeln!(
                out,
                "           {}",
                p.dim(&format!("… and {} more (use -v)", grouped.len() - limit))
            );
        }
    }
    if !shown_any {
        let _ = writeln!(out, "\n  {}", p.dim("No findings."));
    }

    // Files, deduplicated by path, most interesting first.
    let mut files: Vec<(String, Vec<Touch>, bool)> = Vec::new();
    for f in &r.files {
        if f.path == "." || (!f.reachable && !o.verbose) {
            continue;
        }
        let path = clean(&f.path);
        match files.iter_mut().find(|(p, _, _)| *p == path) {
            Some((_, hows, root)) => {
                if !hows.contains(&f.how) {
                    hows.push(f.how);
                }
                *root |= f.as_root;
            }
            None => files.push((path, vec![f.how], f.as_root)),
        }
    }
    if !files.is_empty() {
        let _ = writeln!(out, "\n  {}", p.bold("FILES IT TOUCHES"));
        let width = files
            .iter()
            .map(|(path, _, _)| shorten(path, 60).chars().count())
            .max()
            .unwrap_or(0)
            .min(60);
        let limit = if o.verbose { usize::MAX } else { 12 };
        for (path, hows, root) in files.iter().take(limit) {
            let hows: Vec<&str> = hows.iter().map(|h| h.id()).collect();
            let root = if *root { " (root)" } else { "" };
            let path = shorten(path, 60);
            let pad = width.saturating_sub(path.chars().count());
            let _ = writeln!(
                out,
                "    {}{}  {}",
                path,
                " ".repeat(pad),
                p.dim(&format!("{}{}", hows.join(", "), root))
            );
        }
        if files.len() > limit {
            let _ = writeln!(
                out,
                "    {}",
                p.dim(&format!("… and {} more (use -v)", files.len() - limit))
            );
        }
    }

    let mut urls: Vec<(String, &str)> = Vec::new();
    for u in &r.urls {
        let url = clean(&u.url);
        if !urls.iter().any(|(x, _)| *x == url) {
            urls.push((url, u.action));
        }
    }
    if !urls.is_empty() {
        let _ = writeln!(out, "\n  {}", p.bold("URLS"));
        let limit = if o.verbose { usize::MAX } else { 10 };
        for (url, action) in urls.iter().take(limit) {
            let _ = writeln!(out, "    {:<8} {}", p.dim(action), shorten(url, 100));
        }
        if urls.len() > limit {
            let _ = writeln!(
                out,
                "    {}",
                p.dim(&format!("… and {} more (use -v)", urls.len() - limit))
            );
        }
    }

    let (glyph, words) = verdict(r.max_severity());
    let counts: Vec<String> = Severity::ALL
        .iter()
        .filter(|s| **s != Severity::Info)
        .map(|s| (s, r.count(*s)))
        .filter(|(_, n)| *n > 0)
        .map(|(s, n)| p.sev(*s, &format!("{n} {}", plural(s.id(), n))))
        .collect();
    let _ = writeln!(out);
    let _ = writeln!(out, "  {glyph} {}", p.bold(words));
    if !counts.is_empty() {
        let _ = writeln!(out, "     {}", counts.join(p.dim(" · ").as_str()));
    }
    let serious_unreachable = r
        .findings
        .iter()
        .filter(|f| !f.reachable && f.severity >= Severity::Warn)
        .count();
    if serious_unreachable > 0 {
        let more = if o.verbose { "" } else { " (use -v)" };
        let _ = writeln!(
            out,
            "     {}",
            p.sev(
                Severity::Warn,
                &format!(
                    "{} {serious_unreachable} {} in functions soothsay thinks are never called{more}",
                    icon(Severity::Warn),
                    if serious_unreachable == 1 {
                        "warning/danger"
                    } else {
                        "warnings/dangers"
                    }
                )
            )
        );
    }
    let quiet_unreachable = hidden_unreachable.saturating_sub(serious_unreachable);
    if quiet_unreachable > 0 {
        let _ = writeln!(
            out,
            "     {}",
            p.dim(&format!(
                "{quiet_unreachable} more {} in never-called functions hidden (use -v)",
                plural("note", quiet_unreachable)
            ))
        );
    }
    if hidden_info > 0 {
        let _ = writeln!(
            out,
            "     {}",
            p.dim(&format!(
                "{hidden_info} low-level {} hidden (use -v)",
                plural("note", hidden_info)
            ))
        );
    }
    let _ = writeln!(
        out,
        "     {}",
        p.dim("soothsay reads scripts; it doesn't run them. Advisory, not a sandbox.")
    );
    out
}

fn plural(word: &str, n: usize) -> String {
    let word = match word {
        "warn" => "warning",
        other => other,
    };
    if n == 1 {
        word.to_string()
    } else {
        format!("{word}s")
    }
}

/// JSON escaping per RFC 8259.
pub fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{2028}' || c == '\u{2029}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn opt(s: &Option<String>) -> String {
    s.as_deref().map(json_str).unwrap_or_else(|| "null".into())
}

pub fn json(r: &Report, source: &str) -> String {
    let mut out = String::from("{\n");
    let _ = writeln!(out, "  \"schema_version\": 1,");
    let _ = writeln!(out, "  \"tool\": \"soothsay\",");
    let _ = writeln!(
        out,
        "  \"version\": {},",
        json_str(env!("CARGO_PKG_VERSION"))
    );
    let _ = writeln!(out, "  \"source\": {},", json_str(source));
    let _ = writeln!(out, "  \"sha256\": {},", json_str(&r.sha256));
    let _ = writeln!(out, "  \"lines\": {},", r.lines);
    let _ = writeln!(out, "  \"interpreter\": {},", json_str(&r.interpreter));
    let max = r
        .max_severity()
        .map(|s| json_str(s.id()))
        .unwrap_or_else(|| "null".into());
    let _ = writeln!(out, "  \"max_severity\": {max},");
    let counts: Vec<String> = Severity::ALL
        .iter()
        .map(|s| format!("\"{}\": {}", s.id(), r.count(*s)))
        .collect();
    let _ = writeln!(out, "  \"counts\": {{ {} }},", counts.join(", "));

    let findings: Vec<String> = r
        .findings
        .iter()
        .map(|f| {
            format!(
                "    {{ \"category\": {}, \"severity\": {}, \"line\": {}, \"message\": {}, \"detail\": {}, \"function\": {}, \"reachable\": {}, \"as_root\": {} }}",
                json_str(f.category.id()),
                json_str(f.severity.id()),
                f.line,
                json_str(&f.message),
                opt(&f.detail),
                opt(&f.function),
                f.reachable,
                f.as_root
            )
        })
        .collect();
    let _ = writeln!(out, "  \"findings\": [\n{}\n  ],", findings.join(",\n"));

    let files: Vec<String> = r
        .files
        .iter()
        .map(|f| {
            format!(
                "    {{ \"path\": {}, \"how\": {}, \"line\": {}, \"as_root\": {}, \"reachable\": {} }}",
                json_str(&f.path),
                json_str(f.how.id()),
                f.line,
                f.as_root,
                f.reachable
            )
        })
        .collect();
    let _ = writeln!(out, "  \"files\": [\n{}\n  ],", files.join(",\n"));

    let urls: Vec<String> = r
        .urls
        .iter()
        .map(|u| {
            format!(
                "    {{ \"url\": {}, \"action\": {}, \"line\": {} }}",
                json_str(&u.url),
                json_str(u.action),
                u.line
            )
        })
        .collect();
    let _ = writeln!(out, "  \"urls\": [\n{}\n  ],", urls.join(",\n"));

    let funcs: Vec<String> = r
        .functions
        .iter()
        .map(|(n, called)| {
            format!(
                "    {{ \"name\": {}, \"called\": {} }}",
                json_str(n),
                called
            )
        })
        .collect();
    let _ = writeln!(out, "  \"functions\": [\n{}\n  ]", funcs.join(",\n"));
    out.push_str("}\n");
    out.replace("[\n\n  ]", "[]")
}
