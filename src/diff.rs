//! What changed in a script's *behaviour* between two versions.
//!
//! Text diffs of installers are noisy: a reformatted function or a moved
//! block changes hundreds of lines and nothing about what the script does.
//! [`compare`] matches findings, files and URLs by what they are (ignoring
//! line numbers), so the result reads "now also edits ~/.zshrc" rather than
//! "lines 120-180 changed".

use std::collections::BTreeSet;
use std::fmt::Write as _;

use crate::render::{clean, json_str, verdict};
use crate::{Category, Report, Severity};

/// A finding as it matters for a diff: what happens, not where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub category: Category,
    pub severity: Severity,
    pub message: String,
    /// First line it appears on, in the version it belongs to.
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportDiff {
    /// Findings only the new version has.
    pub added: Vec<Change>,
    /// Findings only the old version has.
    pub removed: Vec<Change>,
    /// `(path, how)` touched only by the new version.
    pub files_added: Vec<(String, &'static str)>,
    pub files_removed: Vec<(String, &'static str)>,
    /// `(url, action)` used only by the new version.
    pub urls_added: Vec<(String, &'static str)>,
    pub urls_removed: Vec<(String, &'static str)>,
    /// Highest live severity, old and new.
    pub verdict: (Option<Severity>, Option<Severity>),
    pub lines: (usize, usize),
    pub sha256: (String, String),
}

impl ReportDiff {
    /// True if the two scripts behave differently, as far as soothsay can tell.
    /// Byte or line-count changes alone don't count.
    pub fn changed(&self) -> bool {
        !(self.added.is_empty()
            && self.removed.is_empty()
            && self.files_added.is_empty()
            && self.files_removed.is_empty()
            && self.urls_added.is_empty()
            && self.urls_removed.is_empty())
            || self.verdict.0 != self.verdict.1
    }
}

type Key = (Category, Severity, String);

/// Findings at notice level or above, one entry per distinct thing, with the
/// first line each appears on. Info-level bookkeeping is left out: it changes
/// with harmless refactors and would make every diff noisy.
fn changes(r: &Report) -> Vec<Change> {
    let mut seen = BTreeSet::new();
    let mut out: Vec<Change> = Vec::new();
    let mut live: Vec<_> = r
        .findings
        .iter()
        .filter(|f| f.severity > Severity::Info)
        .collect();
    live.sort_by_key(|f| f.line);
    for f in live {
        let key: Key = (f.category, f.severity, f.message.clone());
        if seen.insert(key) {
            out.push(Change {
                category: f.category,
                severity: f.severity,
                message: f.message.clone(),
                line: f.line,
            });
        }
    }
    out
}

fn only_in<T: Clone + Ord>(a: &[T], b: &[T]) -> Vec<T> {
    let b: BTreeSet<&T> = b.iter().collect();
    let mut seen = BTreeSet::new();
    a.iter()
        .filter(|x| !b.contains(x) && seen.insert(*x))
        .cloned()
        .collect()
}

/// Compare two reports by behaviour.
pub fn compare(old: &Report, new: &Report) -> ReportDiff {
    let (o, n) = (changes(old), changes(new));
    let key = |c: &Change| -> Key { (c.category, c.severity, c.message.clone()) };
    let o_keys: BTreeSet<Key> = o.iter().map(key).collect();
    let n_keys: BTreeSet<Key> = n.iter().map(key).collect();
    let files = |r: &Report| -> Vec<(String, &'static str)> {
        r.files
            .iter()
            .filter(|f| f.path != ".")
            .map(|f| (f.path.clone(), f.how.id()))
            .collect()
    };
    let urls = |r: &Report| -> Vec<(String, &'static str)> {
        r.urls.iter().map(|u| (u.url.clone(), u.action)).collect()
    };
    ReportDiff {
        added: n
            .iter()
            .filter(|c| !o_keys.contains(&key(c)))
            .cloned()
            .collect(),
        removed: o
            .iter()
            .filter(|c| !n_keys.contains(&key(c)))
            .cloned()
            .collect(),
        files_added: only_in(&files(new), &files(old)),
        files_removed: only_in(&files(old), &files(new)),
        urls_added: only_in(&urls(new), &urls(old)),
        urls_removed: only_in(&urls(old), &urls(new)),
        verdict: (old.max_severity(), new.max_severity()),
        lines: (old.lines, new.lines),
        sha256: (old.sha256.clone(), new.sha256.clone()),
    }
}

fn icon(s: Severity) -> &'static str {
    match s {
        Severity::Danger => "✖",
        Severity::Warn => "▲",
        Severity::Notice => "●",
        Severity::Info => "·",
    }
}

fn level(s: Option<Severity>) -> &'static str {
    s.map_or("none", Severity::id)
}

fn short(sha: &str) -> String {
    if sha.len() > 12 {
        format!("{}…", &sha[..12])
    } else {
        sha.to_string()
    }
}

/// Human-readable diff. `+` is new behaviour, `-` is behaviour that went away.
pub fn text(d: &ReportDiff, old_name: &str, new_name: &str, color: bool) -> String {
    let paint = |code: &str, s: &str| {
        if color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };
    let add = |s: &str| paint("32", s);
    let del = |s: &str| paint("31", s);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "\n🔮 soothsay diff  {} → {}",
        clean(old_name),
        clean(new_name)
    );
    let _ = writeln!(
        out,
        "   {}",
        paint(
            "2",
            &format!(
                "{} → {} lines · sha256 {} → {}",
                d.lines.0,
                d.lines.1,
                short(&d.sha256.0),
                short(&d.sha256.1)
            )
        )
    );
    if d.verdict.0 != d.verdict.1 {
        let (_, from) = verdict(d.verdict.0);
        let (_, to) = verdict(d.verdict.1);
        let _ = writeln!(
            out,
            "\n  VERDICT  {} → {}\n           {from}\n         → {to}",
            level(d.verdict.0),
            level(d.verdict.1)
        );
    }

    if !d.added.is_empty() || !d.removed.is_empty() {
        let _ = writeln!(out, "\n  BEHAVIOUR");
        let row = |sign: &str, c: &Change| {
            format!(
                "  {sign} {}  ({} {} · {} · L{})",
                clean(&c.message),
                icon(c.severity),
                c.severity.id(),
                c.category.id(),
                c.line
            )
        };
        for c in &d.added {
            let _ = writeln!(out, "{}", add(&row("+", c)));
        }
        for c in &d.removed {
            let _ = writeln!(out, "{}", del(&row("-", c)));
        }
    }

    let list = |out: &mut String,
                title: &str,
                plus: &[(String, &'static str)],
                minus: &[(String, &'static str)],
                path_first: bool| {
        if plus.is_empty() && minus.is_empty() {
            return;
        }
        let _ = writeln!(out, "\n  {title}");
        let fmt = |(a, b): &(String, &'static str)| {
            if path_first {
                format!("{}  {b}", clean(a))
            } else {
                format!("{b:<8} {}", clean(a))
            }
        };
        for x in plus {
            let _ = writeln!(out, "{}", add(&format!("  + {}", fmt(x))));
        }
        for x in minus {
            let _ = writeln!(out, "{}", del(&format!("  - {}", fmt(x))));
        }
    };
    list(&mut out, "FILES", &d.files_added, &d.files_removed, true);
    list(&mut out, "URLS", &d.urls_added, &d.urls_removed, false);

    let n = d.added.len()
        + d.removed.len()
        + d.files_added.len()
        + d.files_removed.len()
        + d.urls_added.len()
        + d.urls_removed.len();
    let _ = writeln!(out);
    if d.changed() {
        let _ = writeln!(
            out,
            "  {}",
            paint(
                "1",
                &format!(
                    "Behaviour changed: {n} difference{}.",
                    if n == 1 { "" } else { "s" }
                )
            )
        );
    } else if d.sha256.0 == d.sha256.1 {
        let _ = writeln!(out, "  Identical bytes.");
    } else {
        let _ = writeln!(
            out,
            "  No behaviour change soothsay can see (the bytes differ)."
        );
    }
    out
}

/// Machine-readable diff.
pub fn json(d: &ReportDiff, old_name: &str, new_name: &str) -> String {
    let changes = |cs: &[Change]| -> String {
        let items: Vec<String> = cs
            .iter()
            .map(|c| {
                format!(
                    "{{ \"category\": {}, \"severity\": {}, \"message\": {}, \"line\": {} }}",
                    json_str(c.category.id()),
                    json_str(c.severity.id()),
                    json_str(&c.message),
                    c.line
                )
            })
            .collect();
        format!("[{}]", items.join(", "))
    };
    let pairs = |xs: &[(String, &'static str)], a: &str, b: &str| -> String {
        let items: Vec<String> = xs
            .iter()
            .map(|(x, y)| format!("{{ \"{a}\": {}, \"{b}\": {} }}", json_str(x), json_str(y)))
            .collect();
        format!("[{}]", items.join(", "))
    };
    let sev = |s: Option<Severity>| s.map_or("null".to_string(), |s| json_str(s.id()));
    let mut out = String::from("{\n");
    let _ = writeln!(out, "  \"tool\": \"soothsay\",");
    let _ = writeln!(out, "  \"schema_version\": 1,");
    let _ = writeln!(out, "  \"kind\": \"diff\",");
    let _ = writeln!(
        out,
        "  \"old\": {{ \"source\": {}, \"sha256\": {}, \"lines\": {}, \"max_severity\": {} }},",
        json_str(old_name),
        json_str(&d.sha256.0),
        d.lines.0,
        sev(d.verdict.0)
    );
    let _ = writeln!(
        out,
        "  \"new\": {{ \"source\": {}, \"sha256\": {}, \"lines\": {}, \"max_severity\": {} }},",
        json_str(new_name),
        json_str(&d.sha256.1),
        d.lines.1,
        sev(d.verdict.1)
    );
    let _ = writeln!(out, "  \"changed\": {},", d.changed());
    let _ = writeln!(out, "  \"findings_added\": {},", changes(&d.added));
    let _ = writeln!(out, "  \"findings_removed\": {},", changes(&d.removed));
    let _ = writeln!(
        out,
        "  \"files_added\": {},",
        pairs(&d.files_added, "path", "how")
    );
    let _ = writeln!(
        out,
        "  \"files_removed\": {},",
        pairs(&d.files_removed, "path", "how")
    );
    let _ = writeln!(
        out,
        "  \"urls_added\": {},",
        pairs(&d.urls_added, "url", "action")
    );
    let _ = writeln!(
        out,
        "  \"urls_removed\": {}",
        pairs(&d.urls_removed, "url", "action")
    );
    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze;

    #[test]
    fn moved_lines_are_not_a_change() {
        let a = analyze("echo hi\necho 'export X=1' >> ~/.zshrc\n");
        let b = analyze("\n\n# moved\necho 'export X=1' >> ~/.zshrc\necho hi\n");
        let d = compare(&a, &b);
        assert!(!d.changed(), "{d:?}");
    }

    #[test]
    fn new_behaviour_is_added_and_old_is_removed() {
        let a = analyze("brew install jq\n");
        let b = analyze("echo 'export X=1' >> ~/.zshrc\n");
        let d = compare(&a, &b);
        assert!(d.changed());
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].message, "appends to ~/.zshrc");
        assert_eq!(d.removed.len(), 1);
        assert!(d.removed[0].message.contains("brew"));
        assert_eq!(d.files_added, vec![("~/.zshrc".to_string(), "append")]);
        let t = text(&d, "a.sh", "b.sh", false);
        assert!(t.contains("+ appends to ~/.zshrc"), "{t}");
        assert!(t.contains("- installs packages with brew"), "{t}");
    }

    #[test]
    fn severity_change_is_a_change() {
        let a = analyze("curl -fsSL https://x.dev/i.sh -o i.sh\n");
        let b = analyze("curl -fsSL https://x.dev/i.sh | sh\n");
        let d = compare(&a, &b);
        assert!(d.changed());
        assert_eq!(d.verdict.1, Some(Severity::Warn));
        assert!(d
            .urls_added
            .iter()
            .any(|(u, a)| u == "https://x.dev/i.sh" && *a == "run"));
    }

    #[test]
    fn json_parses() {
        let d = compare(&analyze("echo a\n"), &analyze("sudo rm -rf /opt/x\n"));
        let v = crate::json::parse(&json(&d, "a\"b", "c")).unwrap();
        assert_eq!(v.get("kind").and_then(|k| k.as_str()), Some("diff"));
        assert!(matches!(
            v.get("changed"),
            Some(crate::json::Value::Bool(true))
        ));
    }
}
