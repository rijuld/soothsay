//! The rules: what each command in a script will do to the machine.

use std::collections::{HashMap, HashSet};

use crate::lexer::{is_name, Part, Token, Word};
use crate::parse::{parse, Command, Script};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Notice,
    Warn,
    Danger,
}

impl Severity {
    pub const ALL: [Severity; 4] = [
        Severity::Danger,
        Severity::Warn,
        Severity::Notice,
        Severity::Info,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Notice => "notice",
            Severity::Warn => "warn",
            Severity::Danger => "danger",
        }
    }

    pub fn from_id(s: &str) -> Option<Self> {
        Severity::ALL
            .into_iter()
            .find(|v| v.id() == s || (s == "warning" && *v == Severity::Warn))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    RemoteExec,
    Obfuscation,
    Secrets,
    Security,
    Destructive,
    Persistence,
    ShellProfile,
    Privilege,
    System,
    Packages,
    Config,
    Network,
    BlindSpot,
}

impl Category {
    pub const ALL: [Category; 13] = [
        Category::RemoteExec,
        Category::Obfuscation,
        Category::Secrets,
        Category::Security,
        Category::Destructive,
        Category::Persistence,
        Category::ShellProfile,
        Category::Privilege,
        Category::System,
        Category::Packages,
        Category::Config,
        Category::Network,
        Category::BlindSpot,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Category::RemoteExec => "remote-exec",
            Category::Obfuscation => "obfuscation",
            Category::Secrets => "secrets",
            Category::Security => "security",
            Category::Destructive => "destructive",
            Category::Persistence => "persistence",
            Category::ShellProfile => "rc-edit",
            Category::Privilege => "privilege",
            Category::System => "system",
            Category::Packages => "packages",
            Category::Config => "config",
            Category::Network => "network",
            Category::BlindSpot => "blind-spot",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Category::RemoteExec => "Runs more code from the internet",
            Category::Obfuscation => "Hidden or encoded payloads",
            Category::Secrets => "Touches secrets & credentials",
            Category::Security => "Weakens security settings",
            Category::Destructive => "Deletes things",
            Category::Persistence => "Survives a reboot",
            Category::ShellProfile => "Edits your shell startup files",
            Category::Privilege => "Runs as root",
            Category::System => "Writes outside your home directory",
            Category::Packages => "Installs packages",
            Category::Config => "Changes settings",
            Category::Network => "Network & TLS",
            Category::BlindSpot => "Blind spots: soothsay can't see past these",
        }
    }

    pub fn blurb(self) -> &'static str {
        match self {
            Category::RemoteExec => {
                "pipes a download into a shell, or evals/sources remote content"
            }
            Category::Obfuscation => {
                "decodes base64/hex and executes it, or carries large encoded blobs"
            }
            Category::Secrets => {
                "reads or uploads SSH keys, cloud credentials, keychains, browser data"
            }
            Category::Security => {
                "setuid, world-writable files, Gatekeeper bypass, sudoers, reverse shells"
            }
            Category::Destructive => {
                "rm -rf, dd, mkfs, and deletes that go wrong when a variable is empty"
            }
            Category::Persistence => {
                "cron, launchd, systemd, login items: anything that runs again later"
            }
            Category::ShellProfile => {
                "appends to ~/.zshrc, ~/.bashrc, ~/.profile, fish config, /etc/paths.d"
            }
            Category::Privilege => "sudo, doas, pkexec, su",
            Category::System => "writes to /usr, /etc, /opt, /Library and friends",
            Category::Packages => "apt, brew, dnf, pip, npm -g, cargo install ...",
            Category::Config => "defaults write, git config --global, network settings",
            Category::Network => "what it downloads, uploads, and whether TLS is checked",
            Category::BlindSpot => {
                "eval of dynamic strings, running downloaded binaries, sourcing files"
            }
        }
    }

    pub fn from_id(s: &str) -> Option<Self> {
        Category::ALL.into_iter().find(|c| c.id() == s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub category: Category,
    pub severity: Severity,
    pub line: usize,
    pub message: String,
    pub detail: Option<String>,
    /// The function this happens in, if any.
    pub function: Option<String>,
    /// False when the enclosing function is never called.
    pub reachable: bool,
    pub as_root: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Touch {
    Write,
    Append,
    Modify,
    Create,
    Copy,
    Download,
    Extract,
    Link,
    Delete,
}

impl Touch {
    pub fn id(self) -> &'static str {
        match self {
            Touch::Write => "write",
            Touch::Append => "append",
            Touch::Modify => "modify",
            Touch::Create => "create",
            Touch::Copy => "copy",
            Touch::Download => "download",
            Touch::Extract => "extract",
            Touch::Link => "link",
            Touch::Delete => "delete",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileTouch {
    pub path: String,
    pub how: Touch,
    pub line: usize,
    pub as_root: bool,
    pub function: Option<String>,
    /// False when the enclosing function is never called.
    pub reachable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub url: String,
    pub line: usize,
    /// "download", "upload", "run" or "clone".
    pub action: &'static str,
}

/// Everything soothsay learned about a script.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub lines: usize,
    pub sha256: String,
    pub interpreter: String,
    pub findings: Vec<Finding>,
    pub files: Vec<FileTouch>,
    pub urls: Vec<Url>,
    /// Functions defined, and whether anything calls them.
    pub functions: Vec<(String, bool)>,
}

impl Report {
    /// Number of reachable findings at this severity.
    pub fn count(&self, sev: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.reachable && f.severity == sev)
            .count()
    }

    /// Highest severity among reachable findings.
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings
            .iter()
            .filter(|f| f.reachable)
            .map(|f| f.severity)
            .max()
    }
}

/// Analyze a shell script. Never fails: unknown syntax is skipped, not fatal.
pub fn analyze(src: &str) -> Report {
    let mut a = Analyzer::default();
    a.vars.insert("HOME".into(), "~".into());
    let script = parse(src, 0, None);
    for c in &script.commands {
        let runs_args = matches!(
            c.words.first().map(|w| w.parts.as_slice()),
            Some([Part::Param { name, .. }]) if name == "@" || name == "*"
        );
        if let (true, Some(f)) = (runs_args, &c.function) {
            a.wrappers.insert(f.clone());
        }
    }
    for (f, _) in &script.functions {
        let lower = f.to_ascii_lowercase();
        if lower.contains("sudo") || lower.contains("as_root") {
            a.sudo_wrappers.insert(f.clone());
        }
    }
    a.run(&script);

    // Which functions can actually run? Start from top-level calls and the
    // shell's own hooks, and follow.
    let defined: HashSet<&str> = a.defined.iter().map(|(n, _)| n.as_str()).collect();
    let mut live: HashSet<String> = HashSet::new();
    let mut frontier: Vec<String> = a
        .calls
        .iter()
        .filter(|(from, to)| from.is_none() && defined.contains(to.as_str()))
        .map(|(_, to)| to.clone())
        .chain(
            defined
                .iter()
                .filter(|n| is_shell_hook(n))
                .map(|n| n.to_string()),
        )
        .collect();
    while let Some(f) = frontier.pop() {
        if live.insert(f.clone()) {
            for (from, to) in &a.calls {
                if from.as_deref() == Some(f.as_str())
                    && defined.contains(to.as_str())
                    && !live.contains(to)
                {
                    frontier.push(to.clone());
                }
            }
        }
    }
    // A command name soothsay can't resolve (`"$@"`, `${1:-main}`, a decoded
    // string) could call any function, so none of them can be ruled out.
    let dynamic = a.calls.iter().any(|(from, to)| {
        to == DYNAMIC_CALL
            && from
                .as_deref()
                .map_or(true, |f| live.contains(f) || !defined.contains(f))
    });
    if dynamic {
        live.extend(defined.iter().map(|n| n.to_string()));
    }
    let reachable = |function: &Option<String>| match function {
        None => true,
        Some(name) => live.contains(name) || !defined.contains(name.as_str()),
    };
    for f in &mut a.findings {
        f.reachable = reachable(&f.function);
    }
    for f in &mut a.files {
        f.reachable = reachable(&f.function);
    }

    let mut seen = HashSet::new();
    let functions = a
        .defined
        .iter()
        .filter(|(n, _)| seen.insert(n.clone()))
        .map(|(n, _)| (n.clone(), live.contains(n)))
        .collect();

    Report {
        lines: src.lines().count(),
        sha256: crate::sha256::hex(src.as_bytes()),
        interpreter: interpreter(src),
        findings: a.findings,
        files: a.files,
        urls: a.urls,
        functions,
    }
}

/// Recorded in `calls` for a command whose name can't be known statically.
const DYNAMIC_CALL: &str = "\0dynamic";

/// Functions the shell itself calls: bash/zsh hooks and zsh's `TRAPINT` & co.
fn is_shell_hook(name: &str) -> bool {
    matches!(
        name,
        "command_not_found_handle"
            | "command_not_found_handler"
            | "precmd"
            | "preexec"
            | "chpwd"
            | "periodic"
            | "zshexit"
            | "zshaddhistory"
    ) || name.strip_prefix("TRAP").is_some_and(|sig| {
        !sig.is_empty()
            && sig
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    })
}

/// True if `s`, a resolved word, still names something unknown (`${x}`,
/// `$(…)`) and nothing outside those placeholders makes it a path.
fn unknown_name(s: &str) -> bool {
    if !s.contains("${") && !s.contains("$(") {
        return false;
    }
    let mut rest = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' && matches!(chars.peek(), Some('{') | Some('(')) {
            let (open, close) = if chars.next() == Some('{') {
                ('{', '}')
            } else {
                ('(', ')')
            };
            let mut depth = 1;
            for n in chars.by_ref() {
                if n == open {
                    depth += 1;
                } else if n == close {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
            }
        } else {
            rest.push(c);
        }
    }
    !rest.contains('/')
}

impl Analyzer {
    /// Functions a command might call besides `h.name`, or `None` if its
    /// name is built at runtime and could be anything.
    fn call_targets(&self, h: &Head, function: &Option<String>) -> Option<Vec<String>> {
        match h.name.as_str() {
            "eval" if h.words[1..].iter().any(|w| w.literal().is_none()) => return None,
            "trap"
                if h.words
                    .get(1)
                    .is_some_and(|w| unknown_name(&self.resolve(w))) =>
            {
                return None
            }
            _ => {}
        }
        let first = h.words.first()?;
        // An unquoted `$f` holding `$(…)` arrives here already split into words.
        if let Some(l) = first.literal() {
            return if unknown_name(&l) {
                None
            } else {
                Some(Vec::new())
            };
        }
        if let [Part::Param { name, fallback }] = first.parts.as_slice() {
            let positional = name == "@" || name == "*" || name.chars().all(|c| c.is_ascii_digit());
            if positional {
                // `ensure() { "$@" || exit 1; }`: each call site names the command.
                if function.is_some() && (name == "@" || name == "*") && fallback.is_none() {
                    return Some(Vec::new());
                }
                return None;
            }
            if let Some(vals) = self.ever.get(name) {
                let mut names = Vec::new();
                for v in vals {
                    if unknown_name(v) {
                        return None;
                    }
                    if let Some(n) = v.split_whitespace().next() {
                        names.push(basename(n).to_string());
                    }
                }
                return Some(names);
            }
        }
        if unknown_name(&h.args[0]) {
            return None;
        }
        Some(Vec::new())
    }
}

fn interpreter(src: &str) -> String {
    let first = src.lines().next().unwrap_or("");
    let Some(shebang) = first.strip_prefix("#!") else {
        return "sh".into();
    };
    let mut parts = shebang.split_whitespace();
    let prog = parts.next().unwrap_or("sh");
    let base = basename(prog);
    if base == "env" {
        parts
            .find(|p| !p.starts_with('-'))
            .map(basename)
            .unwrap_or("sh")
            .to_string()
    } else {
        base.to_string()
    }
}

const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "busybox",
];
const INTERPRETERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "mksh",
    "ash",
    "fish",
    "busybox",
    "python",
    "python3",
    "python2",
    "perl",
    "ruby",
    "node",
    "bun",
    "deno",
    "php",
    "pwsh",
    "osascript",
];
const DOWNLOADERS: &[&str] = &[
    "curl", "wget", "wget2", "fetch", "aria2c", "http", "https", "xh",
];
const READERS: &[&str] = &[
    "cat", "head", "tail", "less", "more", "cp", "scp", "rsync", "tar", "zip", "7z", "base64",
    "xxd", "gpg", "openssl", "sqlite3", "strings", "grep",
];
/// Tools recognised from a variable's name, as in `$USABLE_GIT` or `$CURL_CMD`.
const NAMED_TOOLS: &[&str] = &[
    "git", "curl", "wget", "tar", "unzip", "chmod", "chown", "mkdir", "rm", "cp", "mv", "ln",
    "install", "python", "python3", "ruby", "node", "sh", "bash", "brew", "apt", "dnf", "yum",
    "pip", "npm", "stat", "tee", "sed",
];
const PROFILE_FILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".kshrc",
    ".mkshrc",
    "config.fish",
    ".tcshrc",
    ".cshrc",
    ".bash_aliases",
];
const SECRET_PATHS: &[&str] = &[
    "/.ssh/",
    ".ssh/id_",
    "/.aws/",
    "/.gnupg",
    "/.netrc",
    "/.git-credentials",
    "/.docker/config.json",
    "/.kube/config",
    "/.config/gh/",
    "Keychains",
    "Login Data",
    "/Cookies",
    "/.npmrc",
    "/.pypirc",
    "Local Storage/leveldb",
    "/.config/solana",
    "/.bitcoin",
    "/.ethereum",
    "Exodus",
    "/.password-store",
    "1Password",
    "/etc/shadow",
    "/.config/gcloud",
];

/// A command with prefixes like `sudo`/`env` and leading assignments removed.
#[derive(Debug, Default)]
struct Head {
    name: String,
    args: Vec<String>,
    words: Vec<Word>,
    as_root: bool,
}

impl Head {
    fn has(&self, flag: &str) -> bool {
        self.args.iter().skip(1).any(|a| a == flag)
    }

    fn has_short(&self, letter: char) -> bool {
        self.args.iter().skip(1).any(|a| {
            a.starts_with('-') && !a.starts_with("--") && a.len() > 1 && a[1..].contains(letter)
        })
    }

    /// Positional args, skipping flags and the values of flags in `valued`.
    fn positional(&self, valued: &[&str]) -> Vec<String> {
        let mut out = Vec::new();
        let mut i = 1;
        let mut only_positional = false;
        while i < self.args.len() {
            let a = &self.args[i];
            if only_positional {
                out.push(a.clone());
            } else if a == "--" {
                only_positional = true;
            } else if a.starts_with('-') && a.len() > 1 {
                if valued.contains(&a.as_str()) {
                    i += 1;
                }
            } else {
                out.push(a.clone());
            }
            i += 1;
        }
        out
    }

    /// Value of a flag such as `-o file`, `--output file` or `--output=file`.
    fn value(&self, flags: &[&str]) -> Option<String> {
        let mut it = self.args.iter().skip(1);
        while let Some(a) = it.next() {
            for f in flags {
                if a == f {
                    return it.next().cloned();
                }
                if let Some(v) = a.strip_prefix(&format!("{f}=")) {
                    return Some(v.to_string());
                }
            }
        }
        None
    }

    fn line(&self) -> String {
        shorten(&self.args.join(" "), 110)
    }
}

#[derive(Default)]
struct Analyzer {
    vars: HashMap<String, String>,
    /// Every value a variable was ever given, to catch `SUDO=""` / `SUDO=sudo`.
    ever: HashMap<String, Vec<String>>,
    findings: Vec<Finding>,
    files: Vec<FileTouch>,
    urls: Vec<Url>,
    defined: Vec<(String, usize)>,
    calls: Vec<(Option<String>, String)>,
    /// Functions like rustup's `ensure() { "$@" || exit 1; }` that just run
    /// their arguments; `ensure rm -rf x` is really `rm -rf x`.
    wrappers: HashSet<String>,
    /// Functions like Homebrew's `execute_sudo` that run their arguments as root.
    sudo_wrappers: HashSet<String>,
    arrays: HashMap<String, Vec<String>>,
    depth: usize,
    /// Dedup indexes into `findings` / `files`, so big scripts stay linear.
    /// An entry is only trusted if the index still holds a matching item,
    /// since `findings` can be truncated.
    finding_index: HashMap<(Category, usize, String), usize>,
    file_index: HashSet<(String, Touch)>,
    /// Files fetched from the network: (path, url, line).
    downloads: Vec<(String, String, usize)>,
    /// Text of the most recent literal `echo`/`printf`, for `( …; echo x ) | crontab -`.
    last_echo: Option<String>,
}

struct Ctx<'a> {
    line: usize,
    function: &'a Option<String>,
    as_root: bool,
}

impl Analyzer {
    fn run(&mut self, script: &Script) {
        self.defined.extend(script.functions.iter().cloned());
        let cmds = &script.commands;
        let mut start = 0;
        while start < cmds.len() {
            let mut end = start + 1;
            while end < cmds.len() && cmds[end].pipeline == cmds[start].pipeline {
                end += 1;
            }
            let group = &cmds[start..end];
            for idx in 0..group.len() {
                self.command(group, idx);
            }
            start = end;
        }
    }

    fn nested(&mut self, src: &str, first_line: usize, function: &Option<String>) {
        if self.depth > 8 || src.trim().is_empty() {
            return;
        }
        self.depth += 1;
        let script = parse(src, first_line.saturating_sub(1), function.clone());
        self.run(&script);
        self.depth -= 1;
    }

    fn add(
        &mut self,
        cat: Category,
        sev: Severity,
        ctx: &Ctx,
        message: String,
        detail: Option<String>,
    ) {
        let key = (cat, ctx.line, message);
        let dup = self.finding_index.get(&key).is_some_and(|&i| {
            self.findings
                .get(i)
                .is_some_and(|f| f.category == key.0 && f.line == key.1 && f.message == key.2)
        });
        if !dup {
            let (_, _, message) = key.clone();
            self.finding_index.insert(key, self.findings.len());
            self.findings.push(Finding {
                category: cat,
                severity: sev,
                line: ctx.line,
                message,
                detail,
                function: ctx.function.clone(),
                reachable: true,
                as_root: ctx.as_root,
            });
        }
    }

    // ---- resolving words to text -------------------------------------------------

    fn resolve_parts(&self, parts: &[Part]) -> String {
        let mut s = String::new();
        for p in parts {
            match p {
                Part::Lit(t) => s.push_str(t),
                Part::Param { name, .. } if self.arrays.contains_key(array_base(name)) => {
                    s.push_str(&self.arrays[array_base(name)].join(" "));
                }
                Part::Param { name, fallback } => match self.vars.get(name) {
                    // Assigned different values on different branches: don't pretend to know.
                    Some(_) if self.ever.get(name).is_some_and(|v| v.len() > 1) => {
                        s.push_str("${");
                        s.push_str(name);
                        s.push('}');
                    }
                    Some(v) => s.push_str(v),
                    None => match fallback {
                        Some(fb) => s.push_str(&self.resolve_parts(fb)),
                        None => {
                            s.push_str("${");
                            s.push_str(name);
                            s.push('}');
                        }
                    },
                },
                Part::Subst { script, .. } if script.split_whitespace().any(|w| w == "mktemp") => {
                    s.push_str("$(mktemp)");
                }
                Part::Subst { script, .. } => {
                    s.push_str("$(");
                    s.push_str(&shorten(script.trim(), 40));
                    s.push(')');
                }
                Part::ProcSubst { script, .. } => {
                    s.push_str("<(");
                    s.push_str(&shorten(script.trim(), 40));
                    s.push(')');
                }
                Part::Arith(e) => {
                    s.push_str("$((");
                    s.push_str(e);
                    s.push_str("))");
                }
            }
        }
        tidy_path(&s)
    }

    fn resolve(&self, w: &Word) -> String {
        self.resolve_parts(&w.parts)
    }

    /// Every path a word could name. `$PROFILE` set on three `case` branches
    /// yields all three.
    fn alternatives(&self, w: &Word) -> Vec<String> {
        if let Some(Part::Param { name, .. }) = w.parts.first() {
            if let Some(vals) = self.ever.get(name).filter(|v| v.len() > 1) {
                let rest = self.resolve_parts(&w.parts[1..]);
                return vals
                    .iter()
                    .map(|v| tidy_path(&format!("{v}{rest}")))
                    .collect();
            }
        }
        vec![self.resolve(w)]
    }

    fn could_be_sudo(&self, w: &Word) -> bool {
        if let [Part::Param { name, .. }] = w.parts.as_slice() {
            let lower = name.to_ascii_lowercase();
            if lower.contains("sudo") {
                return true;
            }
            if let Some(vals) = self.ever.get(name) {
                return vals
                    .iter()
                    .any(|v| matches!(v.as_str(), "sudo" | "doas" | "sudo -E"));
            }
        }
        false
    }

    /// Strip assignments and prefixes such as `sudo`, `env`, `nohup`.
    fn head(&self, words: &[Word]) -> Option<Head> {
        let mut k = 0;
        while k < words.len() && assignment(&words[k]).is_some() {
            k += 1;
        }
        let mut h = Head::default();
        for w in &words[k..] {
            if self.could_be_sudo(w) && h.args.is_empty() {
                h.as_root = true;
                continue;
            }
            let text = self.resolve(w);
            if text.is_empty() && !w.quoted {
                continue; // a variable that expanded to nothing
            }
            // `$SUDO` resolving to "sudo -E" becomes two args.
            if let [Part::Param { name, .. }] = w.parts.as_slice() {
                if let Some(items) = self.arrays.get(array_base(name)) {
                    for t in items {
                        h.args.push(t.clone());
                        h.words.push(Word {
                            parts: vec![Part::Lit(t.clone())],
                            quoted: true,
                        });
                    }
                    continue;
                }
            }
            let splits = match w.parts.as_slice() {
                [Part::Param { name, .. }] => !w.quoted || name.ends_with("[@]"),
                _ => false,
            };
            if splits && text.contains(' ') {
                for t in text.split_whitespace() {
                    h.args.push(t.to_string());
                    h.words.push(Word {
                        parts: vec![Part::Lit(t.to_string())],
                        quoted: false,
                    });
                }
                continue;
            }
            h.args.push(text);
            h.words.push(w.clone());
        }
        loop {
            let first = h.args.first()?.clone();
            let name = basename(first.trim_start_matches('\\')).to_string();
            let take = |h: &mut Head, n: usize| {
                let n = n.min(h.args.len());
                h.args.drain(..n);
                h.words.drain(..n);
            };
            match name.as_str() {
                "sudo" | "doas" | "run0" | "pkexec" => {
                    h.as_root = true;
                    take(&mut h, 1);
                    while h.args.first().is_some_and(|a| a.starts_with('-')) {
                        let f = h.args[0].clone();
                        if matches!(
                            f.as_str(),
                            "-l" | "-v"
                                | "-k"
                                | "-K"
                                | "-n"
                                | "--list"
                                | "--validate"
                                | "--reset-timestamp"
                        ) && h.args.len() <= 2
                        {
                            return None; // `sudo -v` / `sudo -l cmd` check access, they don't run anything
                        }
                        take(&mut h, 1);
                        if matches!(
                            f.as_str(),
                            "-u" | "-g" | "-C" | "-D" | "-h" | "-p" | "-r" | "-t" | "-U" | "--user"
                        ) {
                            take(&mut h, 1);
                        }
                        if f == "--" {
                            break;
                        }
                    }
                }
                "env" => {
                    take(&mut h, 1);
                    while h
                        .args
                        .first()
                        .is_some_and(|a| a.starts_with('-') || a.contains('='))
                    {
                        let f = h.args[0].clone();
                        take(&mut h, 1);
                        if matches!(f.as_str(), "-u" | "-C" | "-S") {
                            take(&mut h, 1);
                        }
                    }
                }
                "command" | "builtin" => {
                    if matches!(h.args.get(1).map(String::as_str), Some("-v" | "-V")) {
                        return None; // just a lookup
                    }
                    take(&mut h, 1);
                    if h.args.first().is_some_and(|a| a == "-p") {
                        take(&mut h, 1);
                    }
                }
                "exec" | "nohup" | "caffeinate" | "time" | "stdbuf" | "nice" | "ionice"
                | "chronic" => {
                    take(&mut h, 1);
                    while h.args.first().is_some_and(|a| a.starts_with('-')) {
                        let f = h.args[0].clone();
                        take(&mut h, 1);
                        if matches!(f.as_str(), "-n" | "-a") {
                            take(&mut h, 1);
                        }
                    }
                }
                // `busybox wget …`, `busybox sh`: the applet is the real command.
                "busybox" if h.args.get(1).is_some_and(|a| !a.starts_with('-')) => {
                    take(&mut h, 1);
                }
                w if self.sudo_wrappers.contains(w) => {
                    h.as_root = true;
                    take(&mut h, 1);
                }
                w if self.wrappers.contains(w) => take(&mut h, 1),
                "timeout" => {
                    take(&mut h, 1);
                    while h.args.first().is_some_and(|a| a.starts_with('-')) {
                        take(&mut h, 1);
                    }
                    take(&mut h, 1); // duration
                }
                "xargs" => {
                    take(&mut h, 1);
                    while h.args.first().is_some_and(|a| a.starts_with('-')) {
                        let f = h.args[0].clone();
                        take(&mut h, 1);
                        if matches!(f.as_str(), "-I" | "-n" | "-P" | "-L" | "-d" | "-s" | "-E") {
                            take(&mut h, 1);
                        }
                    }
                }
                _ => break,
            }
        }
        h.name = basename(h.args.first()?.trim_start_matches('\\')).to_string();
        // `$USABLE_GIT config …`, `$CURL -fsSL …`: the variable's name says what it is.
        if let Some([Part::Param { name: var, .. }]) = h.words.first().map(|w| w.parts.as_slice()) {
            let lower = var.to_ascii_lowercase();
            if let Some(tool) = lower.split('_').find(|t| NAMED_TOOLS.contains(t)) {
                h.name = tool.to_string();
            }
        }
        Some(h)
    }

    // ---- per-command analysis ----------------------------------------------------

    fn command(&mut self, group: &[Command], idx: usize) {
        let cmd = &group[idx];

        // Command substitutions run before the command itself.
        for w in &cmd.words {
            self.substitutions(w, cmd);
        }
        for r in &cmd.redirects {
            self.substitutions(&r.target, cmd);
            // An unquoted heredoc (`<<EOF`, not `<<'EOF'`) runs its `$(…)` while
            // the body is being written.
            if let (Some(body), false) = (&r.body, r.target.quoted) {
                if body.contains("$(") || body.contains('`') {
                    self.substitutions_in_text(body, cmd.offset + r.body_line, &cmd.function);
                }
            }
        }

        let only_assignments = cmd.words.iter().all(|w| assignment(w).is_some());
        if only_assignments {
            let ctx = Ctx {
                line: cmd.line,
                function: &cmd.function,
                as_root: false,
            };
            for w in &cmd.words {
                if let Some((name, value)) = assignment(w) {
                    self.assign(&name, &value, &ctx);
                }
            }
            self.redirects(cmd, None, group, idx);
            return;
        }

        let Some(h) = self.head(&cmd.words) else {
            // A bare `exec 3<>/dev/tcp/…` or `exec >> ~/.zshrc` has no command
            // left after `exec`, but its redirects still happen.
            self.redirects(cmd, None, group, idx);
            return;
        };
        self.calls.push((cmd.function.clone(), h.name.clone()));
        match self.call_targets(&h, &cmd.function) {
            Some(names) => {
                for n in names {
                    self.calls.push((cmd.function.clone(), n));
                }
            }
            None => self
                .calls
                .push((cmd.function.clone(), DYNAMIC_CALL.to_string())),
        }
        let ctx = Ctx {
            line: cmd.line,
            function: &cmd.function,
            as_root: h.as_root,
        };

        // `LD_PRELOAD=/tmp/x.so ls`: prefix assignments only affect this command,
        // but some of them hijack it.
        for w in cmd.words.iter().take_while(|w| assignment(w).is_some()) {
            if let Some((name, value)) = assignment(w) {
                let v = self.resolve(&value);
                self.env_hijack(&name, &v, &ctx);
            }
        }
        self.ran_download(&h, &ctx);
        if matches!(h.name.as_str(), "echo" | "printf") {
            self.last_echo = echo_code(&h);
        }

        if h.as_root {
            self.add(
                Category::Privilege,
                Severity::Notice,
                &ctx,
                format!("runs as root: {}", h.line()),
                None,
            );
        }
        for a in &h.args {
            if a.contains("/dev/tcp/") || a.contains("/dev/udp/") {
                self.add(
                    Category::Security,
                    Severity::Danger,
                    &ctx,
                    "opens a raw /dev/tcp connection (classic reverse shell)".into(),
                    Some(h.line()),
                );
            }
            if a.len() >= 160
                && a.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c))
            {
                self.add(
                    Category::Obfuscation,
                    Severity::Notice,
                    &ctx,
                    format!("carries a {}-character encoded blob", a.len()),
                    Some(shorten(a, 60)),
                );
            }
        }

        self.redirects(cmd, Some(&h), group, idx);
        self.dispatch(&h, cmd, group, idx, &ctx);
    }

    fn substitutions(&mut self, w: &Word, cmd: &Command) {
        for p in &w.parts {
            match p {
                Part::Subst { script, line } | Part::ProcSubst { script, line } => {
                    self.nested(script, cmd.offset + line, &cmd.function);
                }
                Part::Param {
                    fallback: Some(fb), ..
                } => {
                    let inner = Word {
                        parts: fb.clone(),
                        quoted: true,
                    };
                    self.substitutions(&inner, cmd);
                }
                // `$(( $(curl …|sh) ))`: the shell runs substitutions inside
                // arithmetic before evaluating it.
                Part::Arith(e) if e.contains("$(") || e.contains('`') => {
                    self.substitutions_in_text(e, cmd.line, &cmd.function);
                }
                _ => {}
            }
        }
    }

    fn assign(&mut self, name: &str, value: &Word, ctx: &Ctx) {
        if let Some(inner) = value.literal().and_then(|l| {
            l.strip_prefix('(')
                .and_then(|r| r.strip_suffix(')'))
                .map(String::from)
        }) {
            let items = crate::lexer::tokenize(&inner)
                .into_iter()
                .filter_map(|t| match t {
                    crate::lexer::Token::Word(w, _) => Some(self.resolve(&w)),
                    _ => None,
                })
                .collect();
            self.arrays.insert(name.to_string(), items);
            return;
        }
        let v = self.resolve(value);
        if (name == "HISTFILE" && v == "/dev/null")
            || (matches!(name, "HISTSIZE" | "HISTFILESIZE" | "SAVEHIST") && v == "0")
        {
            self.add(
                Category::Security,
                Severity::Danger,
                ctx,
                format!("switches off shell history ({name}={v})"),
                None,
            );
        }
        self.env_hijack(name, &v, ctx);
        let seen = self.ever.entry(name.to_string()).or_default();
        if !seen.contains(&v) {
            seen.push(v.clone());
        }
        self.vars.insert(name.to_string(), v);
    }

    fn redirects(&mut self, cmd: &Command, h: Option<&Head>, group: &[Command], idx: usize) {
        let name = h.map(|h| h.name.as_str()).unwrap_or("");
        let ctx = Ctx {
            line: cmd.line,
            function: &cmd.function,
            as_root: h.is_some_and(|h| h.as_root),
        };
        for r in &cmd.redirects {
            let target = self.resolve(&r.target);
            if target.contains("/dev/tcp/") || target.contains("/dev/udp/") {
                let msg =
                    format!("redirects into a raw network socket {target} (classic reverse shell)");
                self.add(Category::Security, Severity::Danger, &ctx, msg, None);
            }
            match r.op.as_str() {
                ">" | ">|" | "&>" | ">>" | "&>>" => {
                    let how = if r.op.ends_with(">>") {
                        Touch::Append
                    } else {
                        Touch::Write
                    };
                    let content = self.content(cmd, h, group, idx);
                    let paths = self.alternatives(&r.target);
                    let profiles = paths
                        .iter()
                        .filter(|p| classify(p) == PathKind::ShellProfile)
                        .count();
                    if paths.len() > 1 && profiles == paths.len() {
                        // One finding for "whichever profile your shell uses".
                        let findings = self.findings.len();
                        for path in &paths {
                            self.write(path, how, &ctx, None);
                        }
                        self.findings.truncate(findings);
                        let verb = if how == Touch::Append {
                            "appends to"
                        } else {
                            "overwrites"
                        };
                        let sev = if how == Touch::Append {
                            Severity::Notice
                        } else {
                            Severity::Warn
                        };
                        let msg = format!("{verb} one of {}", paths.join(", "));
                        self.add(Category::ShellProfile, sev, &ctx, msg, content);
                    } else {
                        for path in &paths {
                            self.write(path, how, &ctx, content.clone());
                        }
                    }
                    if let Some(when) = paths.iter().find_map(|p| runs_later(classify(p))) {
                        if let Some(code) = self.raw_content(cmd, h, group, idx) {
                            self.planted(&code, &paths.join(", "), when, &ctx);
                        }
                    }
                }
                "<>" => {
                    for path in self.alternatives(&r.target) {
                        self.write(&path, Touch::Modify, &ctx, None);
                    }
                }
                "<" => {
                    if classify(&target) == PathKind::Secret {
                        self.add(
                            Category::Secrets,
                            Severity::Warn,
                            &ctx,
                            format!("reads {target}"),
                            None,
                        );
                    }
                }
                "<<" | "<<-" | "<<<" => {
                    let body = if r.op == "<<<" {
                        Some(target.clone())
                    } else {
                        r.body.clone()
                    };
                    if SHELLS.contains(&name) && h.is_some_and(|h| h.positional(&[]).is_empty()) {
                        if let Some(b) = body {
                            let line = if r.op == "<<<" {
                                cmd.line
                            } else {
                                cmd.offset + r.body_line
                            };
                            self.nested(&b, line, &cmd.function);
                        }
                    }
                }
                _ => {}
            }
            if r.op == "<<<" {
                self.remote_in_word(&r.target, name, &ctx);
            }
        }
    }

    /// Text being written by `echo … >> f`, `cat <<EOF > f`, `echo … | tee f`.
    fn content(
        &self,
        cmd: &Command,
        h: Option<&Head>,
        group: &[Command],
        idx: usize,
    ) -> Option<String> {
        self.content_raw(cmd, h, group, idx)
            .filter(|c| !c.trim().is_empty())
    }

    fn content_raw(
        &self,
        cmd: &Command,
        h: Option<&Head>,
        group: &[Command],
        idx: usize,
    ) -> Option<String> {
        if let Some(b) = cmd.redirects.iter().find_map(|r| r.body.clone()) {
            return Some(snippet(&b));
        }
        let echo_text = |h: &Head| -> Option<String> {
            if matches!(h.name.as_str(), "echo" | "printf") {
                let text: Vec<&str> = h
                    .args
                    .iter()
                    .skip(1)
                    .filter(|a| !matches!(a.as_str(), "-e" | "-n" | "-en" | "-ne"))
                    .map(String::as_str)
                    .collect();
                Some(snippet(&text.join(" ").replace("\\n", "\n")))
            } else {
                None
            }
        };
        if let Some(t) = h.and_then(echo_text) {
            return Some(t);
        }
        if idx > 0 {
            if let Some(prev) = self.head(&group[idx - 1].words) {
                return echo_text(&prev);
            }
        }
        None
    }

    /// Full text being written, unlike [`Self::content`], which is a one-line snippet.
    fn raw_content(
        &self,
        cmd: &Command,
        h: Option<&Head>,
        group: &[Command],
        idx: usize,
    ) -> Option<String> {
        if let Some(b) = cmd.redirects.iter().find_map(|r| r.body.clone()) {
            return Some(b);
        }
        if let Some(t) = h.and_then(echo_code) {
            return Some(t);
        }
        if idx > 0 {
            return self.head(&group[idx - 1].words).and_then(|p| echo_code(&p));
        }
        None
    }

    /// Code written into a file that runs later (a shell profile, a cron job, a
    /// launch agent). Analyze it as shell code and, if it does something risky,
    /// report that it's being planted. The analysis runs in a scratch analyzer so
    /// the planted code's own effects aren't reported as happening now.
    fn planted(&mut self, code: &str, target: &str, when: &str, ctx: &Ctx) {
        if code.trim().is_empty() {
            return;
        }
        let mut sub = Analyzer {
            vars: self.vars.clone(),
            ever: self.ever.clone(),
            arrays: self.arrays.clone(),
            wrappers: self.wrappers.clone(),
            sudo_wrappers: self.sudo_wrappers.clone(),
            defined: self.defined.clone(),
            depth: self.depth,
            ..Analyzer::default()
        };
        sub.nested(code, ctx.line, ctx.function);
        let escalates = |c: Category| {
            matches!(
                c,
                Category::RemoteExec | Category::Obfuscation | Category::Secrets
            )
        };
        let Some(worst) = sub
            .findings
            .iter()
            .filter(|f| f.severity >= Severity::Warn)
            .max_by_key(|f| (escalates(f.category), f.severity))
        else {
            return;
        };
        let sev = if escalates(worst.category) || worst.severity == Severity::Danger {
            Severity::Danger
        } else {
            Severity::Warn
        };
        let msg = format!("plants code in {target} that {when}: it {}", worst.message);
        self.add(Category::Persistence, sev, ctx, msg, Some(snippet(code)));
    }

    fn write(&mut self, raw: &str, how: Touch, ctx: &Ctx, content: Option<String>) {
        let path = tidy_path(raw);
        if path.is_empty() || path.starts_with('&') {
            return;
        }
        if let Some(dev) = path.strip_prefix("/dev/") {
            if dev.starts_with("disk")
                || dev.starts_with("sd")
                || dev.starts_with("nvme")
                || dev.starts_with("rdisk")
            {
                self.add(
                    Category::Destructive,
                    Severity::Danger,
                    ctx,
                    format!("writes raw bytes to the disk device {path}"),
                    None,
                );
            }
            return;
        }
        if self.file_index.insert((path.clone(), how)) {
            self.files.push(FileTouch {
                path: path.clone(),
                how,
                line: ctx.line,
                as_root: ctx.as_root,
                function: ctx.function.clone(),
                reachable: true,
            });
        }
        let verb = match how {
            Touch::Append => "appends to",
            Touch::Write => "overwrites",
            Touch::Modify => "edits",
            Touch::Link => "symlinks",
            Touch::Delete => "deletes",
            _ => "writes",
        };
        match classify(&path) {
            PathKind::ShellProfile => {
                let sev = if how == Touch::Write {
                    Severity::Warn
                } else {
                    Severity::Notice
                };
                self.add(
                    Category::ShellProfile,
                    sev,
                    ctx,
                    format!("{verb} {path}"),
                    content,
                );
            }
            PathKind::ProbableProfile => {
                self.add(
                    Category::ShellProfile,
                    Severity::Notice,
                    ctx,
                    format!("{verb} {path} (looks like your shell profile)"),
                    content,
                );
            }
            PathKind::Persistence => {
                self.add(
                    Category::Persistence,
                    Severity::Warn,
                    ctx,
                    format!("{verb} a startup item: {path}"),
                    content,
                );
            }
            PathKind::AuthorizedKeys => {
                self.add(
                    Category::Secrets,
                    Severity::Danger,
                    ctx,
                    format!("{verb} {path}: adds keys that can log into this machine"),
                    content,
                );
            }
            PathKind::Sudoers => {
                self.add(
                    Category::Security,
                    Severity::Danger,
                    ctx,
                    format!("{verb} {path}: changes who can become root"),
                    content,
                );
            }
            PathKind::Secret => {
                self.add(
                    Category::Secrets,
                    Severity::Warn,
                    ctx,
                    format!("{verb} {path}"),
                    None,
                );
            }
            PathKind::System(sev) => {
                self.add(Category::System, sev, ctx, format!("{verb} {path}"), None);
            }
            PathKind::Temp | PathKind::Other => {}
        }
    }

    /// `sh -c "$(curl …)"`, `bash <(curl …)`, `eval "$(wget -O- …)"`.
    /// Returns true if the word runs something from the network.
    fn remote_in_word(&mut self, w: &Word, runner: &str, ctx: &Ctx) -> bool {
        let mut found = false;
        for p in &w.parts {
            let (Part::Subst { script, .. } | Part::ProcSubst { script, .. }) = p else {
                continue;
            };
            let inner = parse(script, 0, None);
            let mut prev_decoder = false;
            for c in &inner.commands {
                let Some(h) = self.head(&c.words) else {
                    continue;
                };
                if DOWNLOADERS.contains(&h.name.as_str()) {
                    let url = self
                        .urls_of(&h)
                        .into_iter()
                        .next()
                        .unwrap_or_else(|| "<unknown url>".into());
                    self.urls.push(Url {
                        url: url.clone(),
                        line: ctx.line,
                        action: "run",
                    });
                    let root = if ctx.as_root { " as root" } else { "" };
                    self.add(
                        Category::RemoteExec,
                        Severity::Warn,
                        ctx,
                        format!("downloads and runs {url} with {runner}{root}"),
                        None,
                    );
                    found = true;
                }
                if is_decoder(&h) {
                    prev_decoder = true;
                }
            }
            if prev_decoder {
                self.add(
                    Category::Obfuscation,
                    Severity::Danger,
                    ctx,
                    format!("decodes a hidden payload and runs it with {runner}"),
                    Some(shorten(script.trim(), 100)),
                );
                found = true;
            }
        }
        found
    }

    fn urls_of(&self, h: &Head) -> Vec<String> {
        const VALUED: &[&str] = &[
            "-o",
            "--output",
            "-H",
            "--header",
            "-d",
            "--data",
            "--data-raw",
            "--data-binary",
            "--data-urlencode",
            "-F",
            "--form",
            "-u",
            "--user",
            "-A",
            "--user-agent",
            "-e",
            "--referer",
            "-X",
            "--request",
            "-w",
            "--write-out",
            "--connect-timeout",
            "-m",
            "--max-time",
            "--retry",
            "--proto",
            "-T",
            "--upload-file",
            "--cacert",
            "--cert",
            "-b",
            "--cookie",
            "-c",
            "--cookie-jar",
            "-r",
            "--range",
            "-x",
            "--proxy",
            "--retry-delay",
            "--retry-max-time",
            "-K",
            "--config",
            "-z",
            "--time-cond",
            "--resolve",
            "--limit-rate",
            "-C",
            "--continue-at",
            "-E",
            "--key",
            "--output-dir",
            "-O",
            "--output-document",
            "-P",
            "--directory-prefix",
            "-a",
            "-U",
            "--post-data",
            "--post-file",
            "--body-data",
            "-t",
            "--tries",
            "-i",
            "--input-file",
            "--password",
            "--timeout",
            "-Y",
        ];
        let valued: Vec<&str> = if h.name == "curl" {
            VALUED
                .iter()
                .copied()
                .filter(|f| *f != "-O" && *f != "-P")
                .collect()
        } else {
            VALUED.to_vec()
        };
        h.positional(&valued)
            .into_iter()
            .filter(|a| a.contains("://") || looks_like_url_var(a))
            .collect()
    }

    fn dispatch(&mut self, h: &Head, cmd: &Command, group: &[Command], idx: usize, ctx: &Ctx) {
        let n = h.name.as_str();
        let later: Vec<Head> = group[idx + 1..]
            .iter()
            .filter_map(|c| self.head(&c.words))
            .collect();

        match n {
            _ if DOWNLOADERS.contains(&n) => self.downloader(h, cmd, &later, ctx),
            _ if INTERPRETERS.contains(&n) => self.interpreter(h, cmd, group, idx, ctx),
            "eval" => {
                let mut remote = false;
                for w in &h.words[1..] {
                    remote |= self.remote_in_word(w, "eval", ctx);
                }
                if !remote {
                    let all_literal = h.words[1..].iter().all(|w| w.literal().is_some());
                    if all_literal {
                        let code = h.args[1..].join(" ");
                        self.nested(&code, ctx.line, ctx.function);
                    } else {
                        let from = h.words[1..].iter().find_map(|w| {
                            w.parts.iter().find_map(|p| match p {
                                Part::Subst { script, .. } => {
                                    Some(format!("the output of `{}`", shorten(script.trim(), 50)))
                                }
                                _ => None,
                            })
                        });
                        let what = from.unwrap_or_else(|| "a string built at runtime".into());
                        self.add(
                            Category::BlindSpot,
                            Severity::Notice,
                            ctx,
                            format!("evals {what}"),
                            Some(h.line()),
                        );
                    }
                }
            }
            "source" | "." => {
                if let Some(w) = h.words.get(1) {
                    if !self.remote_in_word(w, n, ctx) {
                        let file = h.args.get(1).cloned().unwrap_or_default();
                        self.add(
                            Category::BlindSpot,
                            Severity::Info,
                            ctx,
                            format!("sources {file} (contents not visible)"),
                            None,
                        );
                    }
                }
            }
            "export" | "local" | "declare" | "typeset" | "readonly" => {
                for w in &h.words[1..] {
                    if let Some((name, value)) = assignment(w) {
                        self.assign(&name, &value, ctx);
                    }
                }
            }
            "trap" => {
                if let Some(code) = h.args.get(1) {
                    self.nested(code, ctx.line, ctx.function);
                }
            }
            "su" => {
                if let Some(code) = h.value(&["-c", "--command"]) {
                    let root = Ctx {
                        line: ctx.line,
                        function: ctx.function,
                        as_root: true,
                    };
                    self.add(
                        Category::Privilege,
                        Severity::Notice,
                        &root,
                        format!("runs as root via su: {}", shorten(&code, 80)),
                        None,
                    );
                    self.nested(&code, ctx.line, ctx.function);
                }
            }
            "rm" | "rmdir" | "unlink" | "shred" | "srm" => self.remove(h, ctx),
            "cp" | "mv" | "install" | "ln" | "rsync" | "ditto" => {
                let pos = h.positional(&[
                    "-m", "--mode", "-o", "--owner", "-g", "--group", "-S", "-t", "-e",
                ]);
                if n == "install" && (h.has("-d") || h.has("--directory")) {
                    for p in &pos {
                        self.write(p, Touch::Create, ctx, None);
                    }
                } else if pos.len() >= 2 {
                    let how = if n == "ln" { Touch::Link } else { Touch::Copy };
                    self.write(&pos[pos.len() - 1], how, ctx, None);
                }
                if matches!(n, "cp" | "rsync" | "ditto" | "scp") {
                    self.secret_reads(h, &later, ctx);
                }
            }
            "mkdir" | "touch" => {
                for p in h.positional(&["-m", "--mode"]) {
                    self.write(&p, Touch::Create, ctx, None);
                }
            }
            "tee" => {
                let how = if h.has_short('a') || h.has("--append") {
                    Touch::Append
                } else {
                    Touch::Write
                };
                let content = self.content(cmd, Some(h), group, idx);
                let paths = h.positional(&[]);
                for p in &paths {
                    self.write(p, how, ctx, content.clone());
                }
                if let Some(when) = paths.iter().find_map(|p| runs_later(classify(p))) {
                    if let Some(code) = self.raw_content(cmd, Some(h), group, idx) {
                        self.planted(&code, &paths.join(", "), when, ctx);
                    }
                }
            }
            "alias" => {
                // `alias ls='curl … | sh'`: the body runs wherever the alias is used.
                for w in &h.words[1..] {
                    if let Some((_, value)) = assignment(w) {
                        let body = self.resolve(&value);
                        self.nested(&body, ctx.line, ctx.function);
                    }
                }
            }
            "sed" | "gsed"
                if h.args
                    .iter()
                    .any(|a| a.starts_with("-i") || a == "--in-place") =>
            {
                let pos = h.positional(&["-e", "-f", "-i", "--expression"]);
                if let Some(file) = pos.last() {
                    self.write(file, Touch::Modify, ctx, None);
                }
            }
            "tar" | "bsdtar" | "gtar" => {
                let x = h
                    .args
                    .get(1)
                    .is_some_and(|a| !a.starts_with("--") && a.contains('x'))
                    || h.has("--extract")
                    || h.has_short('x');
                if x {
                    let dir = h
                        .value(&["-C", "--directory"])
                        .unwrap_or_else(|| ".".into());
                    self.write(&dir, Touch::Extract, ctx, None);
                } else {
                    self.secret_reads(h, &later, ctx);
                }
            }
            "unzip" => {
                let dir = h.value(&["-d"]).unwrap_or_else(|| ".".into());
                self.write(&dir, Touch::Extract, ctx, None);
            }
            "dd" => {
                for a in &h.args {
                    if let Some(of) = a.strip_prefix("of=") {
                        self.write(of, Touch::Write, ctx, None);
                    }
                }
            }
            "mkfs" | "newfs" | "wipefs" | "fdisk" | "sfdisk" | "parted" => {
                self.add(
                    Category::Destructive,
                    Severity::Danger,
                    ctx,
                    format!("formats or repartitions disks: {}", h.line()),
                    None,
                );
            }
            _ if n.starts_with("mkfs.") => {
                self.add(
                    Category::Destructive,
                    Severity::Danger,
                    ctx,
                    format!("formats a filesystem: {}", h.line()),
                    None,
                );
            }
            "diskutil"
                if h.args
                    .iter()
                    .any(|a| a.starts_with("erase") || a == "partitionDisk") =>
            {
                self.add(
                    Category::Destructive,
                    Severity::Danger,
                    ctx,
                    format!("erases a disk: {}", h.line()),
                    None,
                );
            }
            "chmod" => self.chmod(h, ctx),
            "chown" | "chgrp" => {
                let pos = h.positional(&[]);
                if let Some((owner, targets)) = pos.split_first() {
                    for t in targets {
                        if let PathKind::System(_) = classify(t) {
                            self.add(
                                Category::System,
                                Severity::Notice,
                                ctx,
                                format!("changes owner of {t} to {owner}"),
                                None,
                            );
                        }
                    }
                }
            }
            "xattr" => {
                let joined = h.args.join(" ");
                if joined.contains("com.apple.quarantine") || h.has_short('c') {
                    self.add(
                        Category::Security,
                        Severity::Warn,
                        ctx,
                        "strips macOS quarantine so Gatekeeper won't check the download".into(),
                        Some(h.line()),
                    );
                }
            }
            "spctl" => {
                if h.has("--master-disable") || h.has("--global-disable") {
                    self.add(
                        Category::Security,
                        Severity::Danger,
                        ctx,
                        "turns Gatekeeper off for the whole machine".into(),
                        None,
                    );
                } else if h.has("--add") {
                    self.add(
                        Category::Security,
                        Severity::Warn,
                        ctx,
                        "adds a Gatekeeper exception".into(),
                        Some(h.line()),
                    );
                }
            }
            "csrutil" if h.has("disable") => {
                self.add(
                    Category::Security,
                    Severity::Danger,
                    ctx,
                    "disables System Integrity Protection".into(),
                    None,
                );
            }
            "crontab" => {
                if h.has("-r") {
                    self.add(
                        Category::Destructive,
                        Severity::Warn,
                        ctx,
                        "removes your entire crontab".into(),
                        None,
                    );
                } else if !h.has("-l") {
                    let content = self.content(cmd, Some(h), group, idx);
                    self.add(
                        Category::Persistence,
                        Severity::Warn,
                        ctx,
                        "installs a crontab (runs on a schedule)".into(),
                        content,
                    );
                    // `(crontab -l; echo "* * * * * cmd") | crontab -`: the echo sits
                    // in a group in front of the pipe.
                    let table = self.raw_content(cmd, Some(h), group, idx).or_else(|| {
                        (idx == 0 && cmd.stage > 0)
                            .then(|| self.last_echo.clone())
                            .flatten()
                    });
                    if let Some(table) = table {
                        let jobs = cron_commands(&table);
                        self.planted(&jobs, "your crontab", "runs on a schedule", ctx);
                    }
                }
            }
            "launchctl" => {
                let sub = h.args.get(1).map(String::as_str).unwrap_or("");
                match sub {
                    "load" | "bootstrap" | "enable" | "submit" | "kickstart" => {
                        self.add(
                            Category::Persistence,
                            Severity::Warn,
                            ctx,
                            format!("registers a launchd job: {}", h.line()),
                            None,
                        );
                    }
                    "setenv" => self.add(
                        Category::Config,
                        Severity::Notice,
                        ctx,
                        format!("sets a login-wide environment variable: {}", h.line()),
                        None,
                    ),
                    _ => {}
                }
            }
            "systemctl" => {
                if h.has("enable") {
                    self.add(
                        Category::Persistence,
                        Severity::Warn,
                        ctx,
                        format!("enables a systemd service: {}", h.line()),
                        None,
                    );
                } else if h.has("start") || h.has("restart") {
                    self.add(
                        Category::Config,
                        Severity::Notice,
                        ctx,
                        format!("starts a service: {}", h.line()),
                        None,
                    );
                }
            }
            "update-rc.d" | "chkconfig" | "rc-update" => {
                self.add(
                    Category::Persistence,
                    Severity::Warn,
                    ctx,
                    format!("registers a boot-time service: {}", h.line()),
                    None,
                );
            }
            "security" => {
                let sub = h.args.get(1).map(String::as_str).unwrap_or("");
                match sub {
                    "find-generic-password"
                    | "find-internet-password"
                    | "dump-keychain"
                    | "export" => {
                        self.add(
                            Category::Secrets,
                            Severity::Danger,
                            ctx,
                            format!("reads the macOS Keychain ({sub})"),
                            None,
                        );
                    }
                    "add-trusted-cert" => {
                        self.add(
                            Category::Security,
                            Severity::Danger,
                            ctx,
                            "installs a trusted root certificate (can intercept HTTPS)".into(),
                            None,
                        );
                    }
                    _ => {}
                }
            }
            "update-ca-certificates" | "update-ca-trust" | "trust" => {
                self.add(
                    Category::Security,
                    Severity::Warn,
                    ctx,
                    "changes the system's trusted certificates".into(),
                    None,
                );
            }
            "defaults" if h.has("write") || h.has("delete") => {
                self.add(
                    Category::Config,
                    Severity::Notice,
                    ctx,
                    format!("changes macOS preferences: {}", h.line()),
                    None,
                );
            }
            "git" if h.has("config") && (h.has("--global") || h.has("--system")) => {
                self.add(
                    Category::Config,
                    Severity::Notice,
                    ctx,
                    format!("changes your global git config: {}", h.line()),
                    None,
                );
            }
            "git" if h.has("clone") => {
                for u in h
                    .positional(&[
                        "-b", "--branch", "--depth", "-c", "--config", "-o", "--origin",
                    ])
                    .into_iter()
                    .skip(1)
                    .take(1)
                {
                    self.urls.push(Url {
                        url: u,
                        line: ctx.line,
                        action: "clone",
                    });
                }
            }
            "npm" | "pnpm" | "yarn" if h.has("config") && h.has("set") => {
                self.add(
                    Category::Config,
                    Severity::Notice,
                    ctx,
                    format!("changes {n} config: {}", h.line()),
                    None,
                );
            }
            "networksetup" | "scutil" | "nmcli" | "resolvectl" => {
                self.add(
                    Category::Config,
                    Severity::Warn,
                    ctx,
                    format!("changes network settings: {}", h.line()),
                    None,
                );
            }
            "iptables" | "ip6tables" | "nft" | "ufw" | "pfctl" | "firewall-cmd" => {
                self.add(
                    Category::Security,
                    Severity::Warn,
                    ctx,
                    format!("changes firewall rules: {}", h.line()),
                    None,
                );
            }
            "useradd" | "adduser" | "usermod" | "groupadd" | "gpasswd" => {
                self.add(
                    Category::Security,
                    Severity::Notice,
                    ctx,
                    format!("creates or changes user accounts: {}", h.line()),
                    None,
                );
            }
            "userdel" | "dscl" | "sysadminctl" | "passwd" | "chpasswd" | "visudo" => {
                self.add(
                    Category::Security,
                    Severity::Warn,
                    ctx,
                    format!("modifies user accounts or passwords: {}", h.line()),
                    None,
                );
            }
            "history" if h.has("-c") || h.has("-w") => {
                self.add(
                    Category::Security,
                    Severity::Danger,
                    ctx,
                    "wipes shell history".into(),
                    None,
                );
            }
            "unset" if h.has("HISTFILE") => {
                self.add(
                    Category::Security,
                    Severity::Danger,
                    ctx,
                    "stops recording shell history".into(),
                    None,
                );
            }
            "kill" | "pkill" | "killall" => {
                self.add(
                    Category::Config,
                    Severity::Notice,
                    ctx,
                    format!("stops running processes: {}", h.line()),
                    None,
                );
            }
            "shutdown" | "reboot" | "halt" | "poweroff" => {
                self.add(
                    Category::Destructive,
                    Severity::Warn,
                    ctx,
                    format!("restarts or powers off the machine: {}", h.line()),
                    None,
                );
            }
            "nc" | "ncat" | "netcat" | "socat" => {
                let joined = h.args.join(" ");
                if h.has("-e")
                    || h.has("-c")
                    || joined.contains("exec:")
                    || joined.contains("EXEC:")
                {
                    self.add(
                        Category::Security,
                        Severity::Danger,
                        ctx,
                        "hands a shell to a network connection (reverse shell)".into(),
                        Some(h.line()),
                    );
                } else if h.has_short('l') || joined.contains("LISTEN") {
                    self.add(
                        Category::Security,
                        Severity::Warn,
                        ctx,
                        "listens for incoming network connections".into(),
                        Some(h.line()),
                    );
                }
                self.secret_reads(h, &later, ctx);
            }
            _ if is_package_manager(h) => {
                let pkgs = h
                    .positional(&[])
                    .into_iter()
                    .filter(|p| !matches!(p.as_str(), "install" | "add" | "i" | "-S" | "-y"))
                    .collect::<Vec<_>>();
                let sev = if h.has("--break-system-packages") {
                    Severity::Warn
                } else {
                    Severity::Notice
                };
                let list = if pkgs.is_empty() {
                    String::new()
                } else {
                    format!(": {}", shorten(&pkgs.join(" "), 80))
                };
                self.add(
                    Category::Packages,
                    sev,
                    ctx,
                    format!("installs packages with {n}{list}"),
                    None,
                );
            }
            _ => {
                if READERS.contains(&n) {
                    self.secret_reads(h, &later, ctx);
                }
                self.unknown_program(h, ctx);
            }
        }

        // Decoders feeding an interpreter: `echo … | base64 -d | sh`.
        if is_decoder(h) {
            if let Some(runner) = later
                .iter()
                .find(|l| INTERPRETERS.contains(&l.name.as_str()) || l.name == "eval")
            {
                self.add(
                    Category::Obfuscation,
                    Severity::Danger,
                    ctx,
                    format!("decodes a hidden payload and pipes it into {}", runner.name),
                    Some(h.line()),
                );
            }
        }
    }

    fn downloader(&mut self, h: &Head, cmd: &Command, later: &[Head], ctx: &Ctx) {
        let urls = self.urls_of(h);
        let insecure = h.has("--insecure")
            || h.has("--no-check-certificate")
            || (h.name == "curl" && h.has_short('k'));
        if insecure {
            self.add(
                Category::Network,
                Severity::Warn,
                ctx,
                "turns off TLS certificate checks".into(),
                Some(h.line()),
            );
        }
        for u in &urls {
            if u.starts_with("http://")
                && !u.starts_with("http://localhost")
                && !u.starts_with("http://127.0.0.1")
            {
                self.add(
                    Category::Network,
                    Severity::Warn,
                    ctx,
                    format!("downloads over plain HTTP: {u}"),
                    None,
                );
            }
        }
        let data = h.value(&[
            "-d",
            "--data",
            "--data-raw",
            "--data-binary",
            "--data-urlencode",
            "-F",
            "--form",
            "-T",
            "--upload-file",
            "--post-data",
            "--post-file",
            "--body-data",
        ]);
        let posts = data.is_some()
            || matches!(
                h.value(&["-X", "--request"]).as_deref(),
                Some("POST" | "PUT")
            );
        if posts {
            let dest = urls.first().cloned().unwrap_or_else(|| "a server".into());
            for u in &urls {
                self.urls.push(Url {
                    url: u.clone(),
                    line: ctx.line,
                    action: "upload",
                });
            }
            let d = data.clone().unwrap_or_default();
            if classify(d.trim_start_matches('@')) == PathKind::Secret || d.contains("/.ssh/") {
                self.add(
                    Category::Secrets,
                    Severity::Danger,
                    ctx,
                    format!("uploads {} to {dest}", d.trim_start_matches('@')),
                    None,
                );
            } else {
                self.add(
                    Category::Network,
                    Severity::Notice,
                    ctx,
                    format!("sends data to {dest}"),
                    data.map(|d| shorten(&d, 90)),
                );
            }
        } else {
            for u in &urls {
                self.urls.push(Url {
                    url: u.clone(),
                    line: ctx.line,
                    action: "download",
                });
            }
        }
        // curl's `-O` takes no value (it names the file after the URL), wget's does.
        let out_flags: &[&str] = if h.name == "curl" {
            &["-o", "--output"]
        } else {
            &["-o", "--output", "-O", "--output-document"]
        };
        let mut outputs = Vec::new();
        if let Some(out) = h.value(out_flags).filter(|o| o != "-") {
            self.write(&out, Touch::Download, ctx, None);
            outputs.push(out);
        }
        // `curl -s url > /tmp/x.sh` (redirects() records the write itself).
        for r in &cmd.redirects {
            if matches!(r.op.as_str(), ">" | ">|" | ">>") && matches!(r.fd, None | Some(1)) {
                outputs.push(self.resolve(&r.target));
            }
        }
        let url = urls
            .first()
            .cloned()
            .unwrap_or_else(|| "<unknown url>".into());
        for out in outputs {
            self.downloads
                .push((tidy_path(&out), url.clone(), ctx.line));
        }

        // `curl … | sh`, `curl … | sudo bash -s -- --flag`
        let mut decoded = false;
        for l in later {
            if is_decoder(l) {
                decoded = true;
            }
            let reads_stdin = l.positional(&["-c"]).iter().all(|p| p == "-") || l.has("-s");
            if INTERPRETERS.contains(&l.name.as_str()) && reads_stdin && !l.has("-c") {
                let url = urls
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "<unknown url>".into());
                if !urls.is_empty() {
                    if let Some(last) = self.urls.last_mut() {
                        last.action = "run";
                    }
                }
                let root = if l.as_root { " as root" } else { "" };
                let sev = if decoded {
                    Severity::Danger
                } else {
                    Severity::Warn
                };
                self.add(
                    Category::RemoteExec,
                    sev,
                    ctx,
                    format!("pipes {url} straight into {}{root}", l.name),
                    None,
                );
                break;
            }
        }
    }

    fn interpreter(&mut self, h: &Head, cmd: &Command, group: &[Command], idx: usize, ctx: &Ctx) {
        let n = h.name.as_str();
        let mut remote = false;
        for w in &h.words[1..] {
            remote |= self.remote_in_word(w, n, ctx);
        }
        if remote {
            return;
        }
        if (idx > 0 || cmd.stage > 0) && self.piped_code(h, cmd, group, idx, ctx) {
            return;
        }
        if n == "osascript" {
            let joined = h.args.join(" ");
            if joined.contains("hidden answer") {
                self.add(
                    Category::Secrets,
                    Severity::Danger,
                    ctx,
                    "shows a fake dialog asking for your password".into(),
                    Some(shorten(&joined, 100)),
                );
            } else if joined.contains("login item") {
                self.add(
                    Category::Persistence,
                    Severity::Warn,
                    ctx,
                    "adds a login item".into(),
                    None,
                );
            }
            return;
        }
        if let Some(code) = h.value(&["-c", "-e", "--eval"]) {
            if SHELLS.contains(&n) {
                self.nested(&code, ctx.line, ctx.function);
            } else {
                self.add(
                    Category::BlindSpot,
                    Severity::Notice,
                    ctx,
                    format!("runs inline {n} code"),
                    Some(shorten(&code, 100)),
                );
            }
            return;
        }
        if !SHELLS.contains(&n) && h.args[0].contains('/') && !is_system_path(&h.args[0]) {
            // `"$BUN_INSTALL/bin/bun" completions`: the program it just installed.
            return self.unknown_program(h, ctx);
        }
        let looks_like_file = |p: &String| {
            p.contains('/')
                || [
                    ".sh", ".bash", ".py", ".js", ".mjs", ".ts", ".rb", ".pl", ".php",
                ]
                .iter()
                .any(|e| p.ends_with(e))
        };
        let script = h
            .positional(&["-o", "-O", "-W", "-X", "-m"])
            .into_iter()
            .find(|p| p != "-")
            .filter(looks_like_file);
        let fed_by_pipe = idx > 0;
        let has_heredoc = cmd
            .redirects
            .iter()
            .any(|r| r.body.is_some() || r.op == "<<<");
        match script {
            Some(file) if !(n == "bash" || n == "sh") || !h.has("-s") => {
                if !is_system_path(&file) {
                    self.add(
                        Category::BlindSpot,
                        Severity::Notice,
                        ctx,
                        format!(
                            "runs the script {file} with {n} (its contents aren't in this file)"
                        ),
                        None,
                    );
                }
            }
            _ if !SHELLS.contains(&n) && (fed_by_pipe || has_heredoc) => {
                self.add(
                    Category::BlindSpot,
                    Severity::Notice,
                    ctx,
                    format!("feeds code to {n} on stdin"),
                    None,
                );
            }
            _ => {}
        }
    }

    /// Run the `$(…)` and backtick substitutions in a piece of text, such as an
    /// arithmetic expression or an unquoted heredoc body, starting on `first_line`.
    fn substitutions_in_text(&mut self, text: &str, first_line: usize, function: &Option<String>) {
        for t in crate::lexer::tokenize(text) {
            let w = match t {
                Token::Word(w, _) => w,
                Token::Redir(r, _) => r.target,
                Token::Op(..) => continue,
            };
            for p in &w.parts {
                if let Part::Subst { script, line } | Part::ProcSubst { script, line } = p {
                    self.nested(script, first_line + line.saturating_sub(1), function);
                }
            }
        }
    }

    /// `BASH_ENV=…`, `LD_PRELOAD=…`: variables that make other programs run code.
    fn env_hijack(&mut self, name: &str, v: &str, ctx: &Ctx) {
        let file_like = v.contains('/') || v.contains('.');
        let msg = match name {
            "BASH_ENV" if file_like => {
                format!("sets BASH_ENV={v}: every later bash script runs that file first")
            }
            "ENV" if file_like => {
                format!("sets ENV={v}: every later sh/interactive shell runs that file first")
            }
            "PROMPT_COMMAND" if !v.is_empty() => format!(
                "sets PROMPT_COMMAND: runs `{}` before every prompt",
                shorten(v, 60)
            ),
            "LD_PRELOAD" | "DYLD_INSERT_LIBRARIES" if !v.is_empty() => {
                format!("sets {name}={v}: injects that library into every program it starts")
            }
            _ => return,
        };
        self.add(Category::Security, Severity::Warn, ctx, msg, None);
    }

    /// `sh /tmp/x.sh`, `. "$tmp"`, `"$tmp/tool"` where that file was downloaded
    /// earlier in the script.
    fn ran_download(&mut self, h: &Head, ctx: &Ctx) {
        if self.downloads.is_empty() {
            return;
        }
        let n = h.name.as_str();
        let norm = |p: &str| tidy_path(p.strip_prefix("./").unwrap_or(p));
        let find = |p: &str| {
            let p = norm(p);
            self.downloads
                .iter()
                .rev()
                .find(|(d, _, _)| norm(d) == p)
                .cloned()
        };
        let (hit, interpreted) = match h.args.first().and_then(|a| find(a)) {
            Some(d) => (Some(d), false),
            None if matches!(n, "." | "source") => (h.args.get(1).and_then(|a| find(a)), true),
            None if INTERPRETERS.contains(&n) => (
                h.positional(&["-o", "-O", "-W", "-X", "-m"])
                    .into_iter()
                    .find(|p| p != "-")
                    .and_then(|p| find(&p)),
                true,
            ),
            None => (None, false),
        };
        let Some((path, url, line)) = hit else {
            return;
        };
        for u in self.urls.iter_mut().filter(|u| u.url == url) {
            u.action = "run";
        }
        let script = interpreted
            || [".sh", ".bash", ".zsh", ".py", ".pl", ".rb"]
                .iter()
                .any(|e| path.ends_with(e) || url.ends_with(e));
        if script {
            let msg = format!("runs {path}, which it downloaded from {url} on line {line}");
            self.add(
                Category::RemoteExec,
                Severity::Warn,
                ctx,
                msg,
                Some(h.line()),
            );
        } else {
            let msg = format!("runs {path}, a program it downloaded from {url} on line {line}");
            self.add(
                Category::RemoteExec,
                Severity::Notice,
                ctx,
                msg,
                Some(h.line()),
            );
        }
    }

    /// `… | sh`: a shell or interpreter reading its program from a pipe. Returns
    /// true if that's reported, here or by a sharper rule elsewhere.
    fn piped_code(
        &mut self,
        h: &Head,
        cmd: &Command,
        group: &[Command],
        idx: usize,
        ctx: &Ctx,
    ) -> bool {
        let reads_stdin = h.positional(&["-c"]).iter().all(|p| p == "-") || h.has("-s");
        if !reads_stdin || h.has("-c") || h.has("-e") {
            return false;
        }
        let n = h.name.as_str();
        let upstream: Vec<(&Command, Option<Head>)> = group[..idx]
            .iter()
            .map(|c| (c, self.head(&c.words)))
            .collect();
        // Downloads and decoders piped into a shell have sharper findings of their own.
        if upstream.iter().any(|(_, u)| {
            u.as_ref()
                .is_some_and(|u| DOWNLOADERS.contains(&u.name.as_str()) || is_decoder(u))
        }) {
            return true;
        }
        // `echo 'code' | sh`, `cat <<EOF | sh`: the code is right here, so read it.
        if let ([(src, Some(u))], true) = (upstream.as_slice(), cmd.stage == idx) {
            let literal = if u.name == "cat" && u.positional(&[]).is_empty() {
                src.redirects
                    .iter()
                    .find(|r| r.body.is_some() || r.op == "<<<")
                    .map(|r| match &r.body {
                        Some(b) => (b.clone(), src.offset + r.body_line),
                        None => (self.resolve(&r.target), src.line),
                    })
            } else if u.words.iter().all(|w| w.literal().is_some()) {
                echo_code(u).map(|c| (c, src.line))
            } else {
                None
            };
            if let Some((code, line)) = literal {
                if SHELLS.contains(&n) {
                    self.nested(&code, line, ctx.function);
                    return true;
                }
                return false; // other languages: "feeds code to python3 on stdin"
            }
        }
        let root = if h.as_root { " as root" } else { "" };
        let network = upstream.iter().find_map(|(c, u)| {
            let tcp = c.redirects.iter().any(|r| {
                let t = self.resolve(&r.target);
                t.contains("/dev/tcp/") || t.contains("/dev/udp/")
            });
            let tool = u.as_ref().is_some_and(|u| {
                matches!(
                    u.name.as_str(),
                    "nc" | "ncat" | "netcat" | "socat" | "telnet"
                ) || (u.name == "openssl" && u.has("s_client"))
            });
            (tcp || tool).then(|| u.as_ref().map(Head::line).unwrap_or_default())
        });
        if let Some(src) = network {
            self.add(
                Category::RemoteExec,
                Severity::Warn,
                ctx,
                format!("pipes a raw network connection straight into {n}{root}"),
                Some(src),
            );
            return true;
        }
        let what = if upstream.is_empty() {
            "a command group".to_string()
        } else {
            let lines: Vec<String> = upstream
                .iter()
                .map(|(c, u)| match u {
                    Some(u) => u.line(),
                    None => format!("line {}", c.line),
                })
                .collect();
            format!("`{}`", shorten(&lines.join(" | "), 60))
        };
        self.add(
            Category::BlindSpot,
            Severity::Warn,
            ctx,
            format!("pipes the output of {what} into {n}{root}: soothsay can't see what it runs"),
            None,
        );
        true
    }

    fn remove(&mut self, h: &Head, ctx: &Ctx) {
        let recursive =
            h.has_short('r') || h.has_short('R') || h.has("--recursive") || h.name == "rmdir";
        for t in h.positional(&[]) {
            let bare = t.trim_end_matches('*').trim_end_matches('/');
            let catastrophic = matches!(
                bare,
                "" | "~" | "." | ".." | "/usr" | "/etc" | "/System" | "/Users" | "/home" | "/var"
            );
            if catastrophic && recursive {
                self.add(
                    Category::Destructive,
                    Severity::Danger,
                    ctx,
                    format!("recursively deletes {t}"),
                    Some(h.line()),
                );
            } else if recursive && t.starts_with("${") && !t.contains(":-") {
                let var = t.trim_start_matches("${").split('}').next().unwrap_or("");
                self.add(
                    Category::Destructive,
                    Severity::Warn,
                    ctx,
                    format!("rm -r on {t}: if ${var} is ever empty this deletes from /"),
                    Some(h.line()),
                );
            } else if recursive {
                let sev = match classify(&t) {
                    PathKind::System(sev) => sev,
                    PathKind::Secret | PathKind::ShellProfile => Severity::Warn,
                    _ => Severity::Info,
                };
                self.add(
                    Category::Destructive,
                    sev,
                    ctx,
                    format!("recursively deletes {t}"),
                    None,
                );
            } else if matches!(classify(&t), PathKind::ShellProfile | PathKind::Secret) {
                self.add(
                    Category::Destructive,
                    Severity::Warn,
                    ctx,
                    format!("deletes {t}"),
                    None,
                );
            }
            if !t.starts_with("$(") {
                self.files.push(FileTouch {
                    path: t.clone(),
                    how: Touch::Delete,
                    line: ctx.line,
                    as_root: ctx.as_root,
                    function: ctx.function.clone(),
                    reachable: true,
                });
            }
        }
    }

    fn chmod(&mut self, h: &Head, ctx: &Ctx) {
        let pos = h.positional(&["--reference"]);
        let Some((mode, targets)) = pos.split_first() else {
            return;
        };
        let targets = targets.join(" ");
        let digits: String = mode.chars().filter(|c| c.is_ascii_digit()).collect();
        let setuid = mode.contains('s')
            || (digits.len() == 4 && matches!(digits.as_bytes()[0], b'2' | b'4' | b'6' | b'7'));
        if setuid {
            self.add(
                Category::Security,
                Severity::Danger,
                ctx,
                format!("sets setuid/setgid on {targets}: it will run with its owner's privileges"),
                None,
            );
        } else if digits.ends_with('7')
            || digits.ends_with('6')
            || mode.contains("o+w")
            || mode.contains("a+w")
        {
            self.add(
                Category::Security,
                Severity::Warn,
                ctx,
                format!("makes {targets} writable by every user (chmod {mode})"),
                None,
            );
        }
    }

    fn secret_reads(&mut self, h: &Head, later: &[Head], ctx: &Ctx) {
        let uploads = later.iter().any(|l| {
            DOWNLOADERS.contains(&l.name.as_str())
                || matches!(l.name.as_str(), "nc" | "ncat" | "netcat" | "socat")
        });
        let copies = matches!(h.name.as_str(), "cp" | "rsync" | "ditto" | "scp");
        let end = if copies {
            h.args.len().saturating_sub(1)
        } else {
            h.args.len()
        };
        for a in h.args.iter().take(end).skip(1) {
            if classify(a) == PathKind::Secret {
                if uploads {
                    self.add(
                        Category::Secrets,
                        Severity::Danger,
                        ctx,
                        format!("reads {a} and sends it over the network"),
                        Some(h.line()),
                    );
                } else {
                    self.add(
                        Category::Secrets,
                        Severity::Warn,
                        ctx,
                        format!("reads {a}"),
                        Some(h.line()),
                    );
                }
            }
        }
    }

    fn unknown_program(&mut self, h: &Head, ctx: &Ctx) {
        let first = &h.args[0];
        if matches!(first.as_str(), "${@}" | "${*}")
            || (first.len() == 4 && first.starts_with("${") && first.as_bytes()[2].is_ascii_digit())
        {
            return; // a helper running its arguments; the call site has the real command
        }
        let via_var = matches!(
            h.words.first().map(|w| w.parts.as_slice()),
            Some([Part::Param { .. }])
        );
        if via_var && NAMED_TOOLS.contains(&h.name.as_str()) && !first.contains('/') {
            return; // `$USABLE_GIT …` is git
        }
        let defined = self.defined.iter().any(|(n, _)| n == &h.name);
        if defined || is_system_path(first) {
            return;
        }
        if let Some(Part::Param { name, .. }) = h.words.first().and_then(|w| w.parts.first()) {
            // `"$@"` / `"$1" --help` inside a helper: the call site shows the real command.
            if name == "@"
                || name == "*"
                || (name.len() == 1 && name.chars().all(|c| c.is_ascii_digit()))
            {
                return;
            }
            let simple = |v: &String| {
                !v.is_empty() && !v.contains('/') && !v.contains('$') && !v.contains(' ')
            };
            if self
                .ever
                .get(name)
                .is_some_and(|vals| vals.iter().filter(|v| !v.is_empty()).all(simple))
                && !first.contains('/')
            {
                return;
            }
            let lower = name.to_ascii_lowercase();
            let pm = ["package", "pkg", "manager", "_pm"]
                .iter()
                .any(|k| lower.contains(k))
                || lower == "pm";
            if pm && h.has("install") {
                let msg = format!(
                    "installs packages with {first}: {}",
                    shorten(&h.positional(&[]).join(" "), 80)
                );
                return self.add(Category::Packages, Severity::Notice, ctx, msg, None);
            }
        }
        if first.contains('/') || first.starts_with("${") || first.starts_with("$(") {
            // For `$_file`, say what it was set to: "(set to $(mktemp)/rustup-init)".
            let hint = first
                .strip_prefix("${")
                .and_then(|r| r.strip_suffix('}'))
                .and_then(|var| self.ever.get(var))
                .and_then(|vals| vals.iter().find(|v| v.contains('/')))
                .map(|v| format!(" (set to {v})"))
                .unwrap_or_default();
            self.add(
                Category::BlindSpot,
                Severity::Notice,
                ctx,
                format!("runs {first}{hint}: a program soothsay can't see inside"),
                Some(h.line()),
            );
        }
    }
}

/// The text an `echo`/`printf` prints, as best we can tell.
fn echo_code(h: &Head) -> Option<String> {
    if !matches!(h.name.as_str(), "echo" | "printf") {
        return None;
    }
    let mut args: Vec<&str> = h
        .args
        .iter()
        .skip(1)
        .map(String::as_str)
        .skip_while(|a| matches!(*a, "-e" | "-n" | "-en" | "-ne" | "-E"))
        .collect();
    // `printf '%s\n' "code"`: the arguments are the text, not the format.
    if h.name == "printf" && args.len() > 1 && args[0].contains('%') {
        args.remove(0);
    }
    let text = args.join(" ").replace("\\n", "\n");
    (!text.trim().is_empty()).then_some(text)
}

/// When code written to a file of this kind will run, if it ever does.
fn runs_later(kind: PathKind) -> Option<&'static str> {
    match kind {
        PathKind::ShellProfile | PathKind::ProbableProfile => Some("runs in every new shell"),
        PathKind::Persistence => Some("runs at login or on a schedule"),
        _ => None,
    }
}

/// A crontab's commands, without their schedule fields.
fn cron_commands(table: &str) -> String {
    table
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            if assignment_text(l) {
                return Some(l.to_string()); // `PATH=…` sets a variable for the jobs
            }
            let fields = if l.starts_with('@') { 1 } else { 5 };
            let mut rest = l;
            for _ in 0..fields {
                rest = rest.trim_start();
                rest = &rest[rest.find(char::is_whitespace)?..];
            }
            Some(rest.trim().to_string())
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn assignment_text(l: &str) -> bool {
    l.split_once('=').is_some_and(|(n, _)| is_name(n))
}

fn is_decoder(h: &Head) -> bool {
    match h.name.as_str() {
        "base64" | "base32" => h.has("-d") || h.has("-D") || h.has("--decode"),
        "xxd" => h.has("-r") || h.has_short('r'),
        "openssl" => h.has("-d") || h.has("base64"),
        "uudecode" | "rev" => true,
        _ => false,
    }
}

fn is_package_manager(h: &Head) -> bool {
    let sub = h.positional(&[]).first().cloned().unwrap_or_default();
    match h.name.as_str() {
        "apt" | "apt-get" | "yum" | "dnf" | "zypper" | "brew" | "port" | "snap" | "flatpak"
        | "pkg" | "emerge" => {
            matches!(sub.as_str(), "install" | "reinstall" | "upgrade")
        }
        "apk" => sub == "add",
        "pacman" => h.args.iter().any(|a| a.starts_with("-S")),
        "pip" | "pip3" | "pipx" | "gem" | "cargo" | "go" | "uv" => {
            sub == "install" || (h.name == "uv" && sub == "tool")
        }
        "npm" | "pnpm" | "yarn" | "bun" => {
            ((sub == "install" || sub == "i" || sub == "add") && (h.has("-g") || h.has("--global")))
                || (h.name == "yarn" && sub == "global")
        }
        _ => false,
    }
}

fn is_system_path(p: &str) -> bool {
    [
        "/bin/",
        "/usr/bin/",
        "/sbin/",
        "/usr/sbin/",
        "/usr/libexec/",
        "/System/",
    ]
    .iter()
    .any(|s| p.starts_with(s))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathKind {
    ShellProfile,
    ProbableProfile,
    Persistence,
    AuthorizedKeys,
    Sudoers,
    Secret,
    System(Severity),
    Temp,
    Other,
}

fn classify(p: &str) -> PathKind {
    let base = basename(p);
    let has = |s: &str| p.contains(s);
    if PROFILE_FILES.contains(&base)
        || [
            "/etc/profile",
            "/etc/paths",
            "/etc/zsh",
            "/etc/bash",
            "fish/conf.d/",
        ]
        .iter()
        .any(|s| has(s))
    {
        return PathKind::ShellProfile;
    }
    let unresolved = p
        .strip_prefix("${")
        .and_then(|r| r.strip_suffix('}'))
        .or_else(|| p.strip_prefix("$(").and_then(|r| r.strip_suffix(')')));
    let tail = basename(p);
    let tail_unresolved =
        (tail.starts_with("${") || tail.starts_with("$(")) && looks_like_profile_name(tail);
    if unresolved.is_some_and(looks_like_profile_name) || tail_unresolved {
        return PathKind::ProbableProfile;
    }
    if has("authorized_keys") {
        return PathKind::AuthorizedKeys;
    }
    if has("sudoers") {
        return PathKind::Sudoers;
    }
    let persistence = [
        "LaunchAgents",
        "LaunchDaemons",
        "/etc/systemd",
        ".config/systemd",
        "/etc/cron",
        "/var/spool/cron",
        "/etc/init.d",
        "rc.local",
        "/autostart",
        "StartupItems",
    ];
    if persistence.iter().any(|s| has(s)) {
        return PathKind::Persistence;
    }
    if SECRET_PATHS.iter().any(|s| has(s))
        || matches!(base, ".env" | ".ssh" | ".aws" | ".gnupg" | ".kube")
    {
        return PathKind::Secret;
    }
    if p.starts_with("/tmp")
        || p.starts_with("/var/tmp")
        || p.starts_with("/var/folders")
        || p.starts_with("$(mktemp")
        || p.starts_with("${TMPDIR")
    {
        return PathKind::Temp;
    }
    if ["/usr/local", "/opt/", "/Applications"]
        .iter()
        .any(|s| p.starts_with(s))
        || p == "/opt"
    {
        return PathKind::System(Severity::Notice);
    }
    if [
        "/etc", "/usr", "/bin", "/sbin", "/Library", "/System", "/var", "/lib", "/boot",
    ]
    .iter()
    .any(|s| p.starts_with(s))
    {
        return PathKind::System(Severity::Warn);
    }
    PathKind::Other
}

fn array_base(name: &str) -> &str {
    name.strip_suffix("[@]")
        .or_else(|| name.strip_suffix("[*]"))
        .unwrap_or(name)
}

/// `${download_url}`, `${1}`, `${@}`: an unresolved value that is probably the URL.
fn looks_like_url_var(a: &str) -> bool {
    let Some(name) = a.strip_prefix("${").and_then(|r| r.strip_suffix('}')) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    ["url", "uri", "link", "endpoint", "mirror", "host"]
        .iter()
        .any(|k| lower.contains(k))
        || name == "@"
        || (name.len() == 1 && name.chars().all(|c| c.is_ascii_digit()))
}

/// `$PROFILE`, `${bash_config}`, `$(nvm_detect_profile)`, but not `$src`.
fn looks_like_profile_name(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    let words: Vec<&str> = lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    let any = |ws: &[&str]| words.iter().any(|w| ws.contains(w));
    any(&[
        "profile", "rc", "rcfile", "rcfiles", "bashrc", "zshrc", "shellrc",
    ]) || (any(&["bash", "zsh", "fish", "shell"]) && any(&["config", "conf", "cfg"]))
}

/// `NAME=value` (the value may contain expansions).
fn assignment(w: &Word) -> Option<(String, Word)> {
    let Some(Part::Lit(first)) = w.parts.first() else {
        return None;
    };
    let eq = first.find('=')?;
    let name = &first[..eq];
    let name = name.strip_suffix('+').unwrap_or(name);
    if !is_name(name) {
        return None;
    }
    let mut parts = Vec::new();
    let rest = &first[eq + 1..];
    if !rest.is_empty() {
        parts.push(Part::Lit(rest.to_string()));
    }
    parts.extend(w.parts[1..].iter().cloned());
    Some((
        name.to_string(),
        Word {
            parts,
            quoted: w.quoted,
        },
    ))
}

fn basename(p: &str) -> &str {
    p.trim_end_matches('/').rsplit('/').next().unwrap_or(p)
}

fn tidy_path(s: &str) -> String {
    let mut out = s.replace("~/./", "~/");
    while out.contains("//") && !out.contains("://") {
        out = out.replace("//", "/");
    }
    out
}

pub(crate) fn shorten(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

fn snippet(s: &str) -> String {
    let lines: Vec<&str> = s.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let mut out = lines
        .iter()
        .take(3)
        .copied()
        .collect::<Vec<_>>()
        .join(" ⏎ ");
    if lines.len() > 3 {
        out.push_str(&format!(" ⏎ … (+{} lines)", lines.len() - 3));
    }
    shorten(&out, 140)
}
