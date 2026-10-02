use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::{self, Stdio};

use soothsay::guard::{self, Decision, Guard, KNOWN_SHELLS, MAX_SCRIPT as MAX_INPUT};
use soothsay::{json, render, Category, Severity};

const HELP: &str = "\
soothsay: read the omens before you `curl | sh`

USAGE
    curl -fsSL https://example.com/install.sh | soothsay [OPTIONS]
    soothsay [OPTIONS] install.sh
    soothsay [OPTIONS] https://example.com/install.sh
    soothsay --diff OLD NEW       (files or URLs)
    soothsay --check-command '<shell command>'
    soothsay hook                 (Claude Code PreToolUse hook; JSON on stdin)

    Reads a shell script and tells you what it will do to your machine before
    you run it: files written, shell profiles edited, sudo, startup items,
    nested downloads, hidden payloads, credential access.

OPTIONS
    -v, --verbose          Show low-level notes and every item (no truncation)
        --json             Machine-readable report on stdout
        --run              After the report, ask on your terminal, then run the
                           *exact bytes* that were analyzed (never re-downloads)
    -y, --yes              With --run: don't ask (policy flags still apply, and a
                           script with danger findings still isn't run)
        --allow-danger     With --run --yes: run even if there are danger findings
        --shell <SH>       Interpreter for --run (default: the script's shebang, else sh)
        --expect-sha256 <HEX>
                           Exit 1 unless the script's sha256 is exactly this
                           (pin the bytes you reviewed earlier)
        --deny <CATS>      Exit 1 if any finding is in these categories
                           (comma-separated ids, or \"all\")
        --fail-on <SEV>    Exit 1 if any finding is at least this severe
                           (notice | warn | danger)
        --ignore-unreachable
                           Let --deny / --fail-on skip findings in functions
                           that look never-called (off by default: a script
                           can hide how it calls them)
        --diff <OLD> <NEW> Show what changed in behaviour between two versions of
                           a script (files or URLs): findings, files and URLs
                           added or removed, verdict. Exit 0 if behaviour is the
                           same, 1 if it changed. Works with --json.
        --cloak-check      With a URL: download it as curl and as a browser and
                           compare. Exit 1 if the server sends different scripts
        --categories       List category ids and exit
        --no-color         Disable colour (also honours NO_COLOR)
    -h, --help             Show this help
    -V, --version          Show version

    Arguments after `--` are passed to the script by --run:
        curl -fsSL https://sh.rustup.rs | soothsay --run -- -y

GUARDING AN AGENT
    --check-command <CMD>  If CMD runs code from the network (`curl … | sh`,
                           `bash <(curl …)`, or a file an earlier checked command
                           downloaded), fetch that script, review it, save the
                           exact bytes, and explain how to run them. Exit 0 if
                           there's nothing to review, 1 if blocked, 3 if it runs
                           reviewed bytes and the user should approve (review on
                           stdout). Use - to read CMD from stdin.
    hook                   The same check as a Claude Code PreToolUse hook: reads
                           the hook JSON on stdin, exits 2 (block) with the
                           review on stderr, asks the user (an \"ask\" decision) before
                           a reviewed script runs, and blocks on any internal error.
    Reviewed scripts go to $SOOTHSAY_CACHE, $XDG_CACHE_HOME/soothsay, or
    ~/.cache/soothsay. Downloads use your `curl`.

EXIT STATUS
    0  report printed (and, with --run, the script's own exit status)
    1  a --deny / --fail-on policy matched
    1  --expect-sha256 did not match
    1  --diff found a behaviour change, or --cloak-check found different bytes
    2  usage or I/O error, or input that isn't a shell script
       (empty, HTML, binary, or over 16 MiB)
";

struct Args {
    file: Option<String>,
    json: bool,
    verbose: bool,
    run: bool,
    yes: bool,
    shell: Option<String>,
    expect_sha256: Option<String>,
    deny: Vec<Category>,
    fail_on: Option<Severity>,
    ignore_unreachable: bool,
    allow_danger: bool,
    cloak_check: bool,
    diff: Option<(String, String)>,
    color: bool,
    script_args: Vec<String>,
}

fn die(msg: &str) -> ! {
    die_with(2, msg)
}

fn die_with(code: i32, msg: &str) -> ! {
    eprintln!("soothsay: {msg}");
    process::exit(code);
}

fn parse_args() -> Args {
    let mut a = Args {
        file: None,
        json: false,
        verbose: false,
        run: false,
        yes: false,
        shell: None,
        expect_sha256: None,
        deny: Vec::new(),
        fail_on: None,
        ignore_unreachable: false,
        allow_danger: false,
        cloak_check: false,
        diff: None,
        color: std::env::var_os("NO_COLOR").is_none() && io::stdout().is_terminal(),
        script_args: Vec::new(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (arg.clone(), None),
        };
        let mut value = |name: &str| {
            inline
                .clone()
                .or_else(|| it.next())
                .unwrap_or_else(|| die(&format!("{name} needs a value")))
        };
        match flag.as_str() {
            "-h" | "--help" => {
                print!("{HELP}");
                process::exit(0);
            }
            "-V" | "--version" => {
                println!("soothsay {}", env!("CARGO_PKG_VERSION"));
                process::exit(0);
            }
            "--categories" => {
                for c in Category::ALL {
                    println!("{:<12} {}", c.id(), c.blurb());
                }
                process::exit(0);
            }
            "-v" | "--verbose" => a.verbose = true,
            "--json" => a.json = true,
            "--run" => a.run = true,
            "-y" | "--yes" => a.yes = true,
            "--no-color" => a.color = false,
            "--ignore-unreachable" => a.ignore_unreachable = true,
            "--allow-danger" => a.allow_danger = true,
            "--cloak-check" => a.cloak_check = true,
            "--diff" => {
                let old = value("--diff");
                let new = it
                    .next()
                    .unwrap_or_else(|| die("--diff needs two scripts: --diff OLD NEW"));
                a.diff = Some((old, new));
            }
            "--shell" => a.shell = Some(value("--shell")),
            "--expect-sha256" => {
                let v = value("--expect-sha256").to_ascii_lowercase();
                if v.len() != 64 || !v.chars().all(|c| c.is_ascii_hexdigit()) {
                    die("--expect-sha256 needs a full 64-character hex sha256");
                }
                a.expect_sha256 = Some(v);
            }
            "--deny" => {
                let v = value("--deny");
                for id in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    if id == "all" {
                        a.deny.extend(Category::ALL);
                    } else {
                        let c = Category::from_id(id).unwrap_or_else(|| {
                            die(&format!("unknown category {id:?} (see --categories)"))
                        });
                        a.deny.push(c);
                    }
                }
            }
            "--fail-on" => {
                let v = value("--fail-on");
                a.fail_on = Some(
                    Severity::from_id(&v)
                        .unwrap_or_else(|| die(&format!("unknown severity {v:?}"))),
                );
            }
            "--" => {
                a.script_args = it.by_ref().collect();
            }
            s if s.starts_with('-') && s != "-" => die(&format!("unknown option {s} (try --help)")),
            _ => {
                if a.file.is_some() {
                    die("only one script at a time");
                }
                a.file = Some(arg);
            }
        }
    }
    a
}

fn main() {
    let mut argv = std::env::args().skip(1);
    match argv.next().as_deref() {
        Some("hook") => hook(),
        Some("--check-command") => {
            let cmd = match argv.next() {
                Some(c) if c == "-" => {
                    let mut s = String::new();
                    io::stdin()
                        .take(1024 * 1024)
                        .read_to_string(&mut s)
                        .unwrap_or_else(|e| die(&format!("reading stdin: {e}")));
                    s
                }
                Some(c) => c,
                None => die("--check-command needs a command (or - for stdin)"),
            };
            let cwd = std::env::current_dir().unwrap_or_else(|e| die(&format!("cwd: {e}")));
            match check(&cmd, cwd, true) {
                Decision::Pass => process::exit(0),
                Decision::Block(msg) => {
                    println!("{msg}");
                    process::exit(1);
                }
                Decision::Ask(msg) => {
                    println!("{msg}");
                    process::exit(3);
                }
            }
        }
        _ => {}
    }
    let args = parse_args();

    if let Some((old, new)) = &args.diff {
        if args.file.is_some() || args.run {
            die("--diff takes exactly two scripts and can't be combined with --run");
        }
        diff_cmd(old, new, &args);
    }
    if args.cloak_check && !args.file.as_deref().is_some_and(is_url) {
        die("--cloak-check needs a URL: soothsay --cloak-check https://example.com/install.sh");
    }

    let (source, bytes) = load(args.file.as_deref());
    if args.cloak_check {
        cloak_check(args.file.as_deref().unwrap_or_default(), &bytes, &args);
    }
    let report = soothsay::analyze_bytes(&bytes);
    if let Some(want) = &args.expect_sha256 {
        if *want != report.sha256 {
            die_with(
                1,
                &format!(
                    "sha256 mismatch: expected {want}, got {}; these are not the bytes you pinned",
                    report.sha256
                ),
            );
        }
    }

    let shell_script = KNOWN_SHELLS.contains(&report.interpreter.as_str());
    if !shell_script {
        eprintln!(
            "soothsay: WARNING: this is a {} script (per its #! line). soothsay only reads \
             shell, so the report below says nothing about what it will do.",
            report.interpreter
        );
    }

    if args.json {
        print!("{}", render::json(&report, &source));
    } else {
        let opts = render::Options {
            color: args.color,
            verbose: args.verbose,
            source,
        };
        // With --run the report goes to stderr so stdout stays the script's.
        let text = render::text(&report, &opts);
        if args.run {
            eprint!("{text}");
        } else {
            print!("{text}");
        }
    }

    let denied: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.reachable || !args.ignore_unreachable)
        .filter(|f| {
            args.deny.contains(&f.category) || args.fail_on.is_some_and(|s| f.severity >= s)
        })
        .collect();
    if !denied.is_empty() {
        let f = denied[0];
        eprintln!(
            "soothsay: policy failed on {} finding(s), first: line {} [{}] {}",
            denied.len(),
            f.line,
            f.category.id(),
            f.message
        );
        process::exit(1);
    }

    if args.run {
        let danger = report
            .findings
            .iter()
            .any(|f| f.severity == Severity::Danger);
        if danger && args.yes && !args.allow_danger {
            eprintln!(
                "soothsay: not running a script with danger findings unattended; \
                 drop --yes to decide yourself, or pass --allow-danger"
            );
            process::exit(1);
        }
        if !shell_script && args.shell.is_none() {
            eprintln!(
                "soothsay: not running a {} script as shell; pass --shell <interpreter> if you really mean to",
                report.interpreter
            );
            process::exit(2);
        }
        let shell = args
            .shell
            .clone()
            .unwrap_or_else(|| report.interpreter.clone());
        process::exit(run(&bytes, &report.sha256, &shell, &args));
    }
}

/// Confirm on the terminal, then run the analyzed bytes from a private temp file.
fn run(bytes: &[u8], sha: &str, shell: &str, args: &Args) -> i32 {
    let tty = File::options().read(true).write(true).open("/dev/tty");
    if !args.yes {
        let Ok(tty) = tty.as_ref() else {
            eprintln!("soothsay: no terminal to confirm on; pass --yes to run without asking");
            return 2;
        };
        let mut w = tty;
        let _ = write!(
            w,
            "\nRun these exact bytes (sha256 {}…) with {shell}? [y/N] ",
            &sha[..12]
        );
        let _ = w.flush();
        let mut answer = String::new();
        let _ = BufReader::new(tty).read_line(&mut answer);
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            eprintln!("Not running it.");
            return 0;
        }
    }

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!("soothsay-{}-{nanos}.sh", process::id()));
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o700);
    }
    let written = opts.open(&path).and_then(|mut f| f.write_all(bytes));
    if let Err(e) = written {
        eprintln!("soothsay: writing temp file: {e}");
        return 2;
    }

    // The script's stdin was its own source; give it the terminal instead so
    // installers that prompt ("Proceed? [y/N]") still work.
    let stdin = File::open("/dev/tty")
        .map(Stdio::from)
        .unwrap_or_else(|_| Stdio::null());
    let status = process::Command::new(shell)
        .arg(&path)
        .args(&args.script_args)
        .stdin(stdin)
        .status();
    let _ = fs::remove_file(&path);
    match status {
        Ok(s) => exit_code(s),
        Err(e) => {
            eprintln!("soothsay: running {shell}: {e}");
            2
        }
    }
}

fn is_url(s: &str) -> bool {
    s.starts_with("https://") || s.starts_with("http://")
}

/// The script to analyze, from stdin, a file or a URL, with the name to show
/// for it. Exits with status 2 on anything that isn't a readable shell script.
fn load(spec: Option<&str>) -> (String, Vec<u8>) {
    let (source, bytes) = match spec {
        None | Some("-") => {
            if io::stdin().is_terminal() {
                eprint!("{HELP}");
                process::exit(2);
            }
            let buf =
                read_capped(io::stdin()).unwrap_or_else(|e| die(&format!("reading stdin: {e}")));
            ("stdin".to_string(), buf)
        }
        Some(url) if is_url(url) => {
            if url.starts_with("http://") {
                eprintln!(
                    "soothsay: note: {} is plain HTTP, so anyone on the network path can change \
                     what you download",
                    render::clean(url)
                );
            }
            let buf = fetch(url)
                .unwrap_or_else(|e| die(&format!("couldn't download {}: {e}", render::clean(url))));
            (render::clean(url), buf)
        }
        Some(path) => {
            let buf = File::open(path)
                .and_then(read_capped)
                .unwrap_or_else(|e| die(&format!("{path}: {e}")));
            (path.rsplit('/').next().unwrap_or(path).to_string(), buf)
        }
    };
    if bytes.len() as u64 > MAX_INPUT {
        die("input is over 16 MiB; that's not an install script, refusing to read it");
    }
    if let Some(why) = guard::not_a_script(&bytes) {
        die(&format!("{source}: {why}"));
    }
    (source, bytes)
}

/// `--diff OLD NEW`: compare two versions of a script by behaviour.
fn diff_cmd(old: &str, new: &str, args: &Args) -> ! {
    if old == "-" && new == "-" {
        die("--diff can read at most one script from stdin");
    }
    let (old_name, old_bytes) = load(Some(old));
    let (new_name, new_bytes) = load(Some(new));
    let d = soothsay::diff::compare(
        &soothsay::analyze_bytes(&old_bytes),
        &soothsay::analyze_bytes(&new_bytes),
    );
    if args.json {
        print!("{}", soothsay::diff::json(&d, &old_name, &new_name));
    } else {
        print!(
            "{}",
            soothsay::diff::text(&d, &old_name, &new_name, args.color)
        );
    }
    process::exit(i32::from(d.changed()));
}

/// A desktop browser's User-Agent, for asking a server what it shows people
/// who look at a script before they pipe it into a shell.
const BROWSER_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                          (KHTML, like Gecko) Chrome/128.0 Safari/537.36";

/// `--cloak-check`: does the server send `curl` a different script than a
/// browser? `as_curl` is what was already downloaded with curl's own agent.
/// Same bytes: say so and carry on with the report. Different: show both
/// hashes and what the difference does, and exit 1.
fn cloak_check(url: &str, as_curl: &[u8], args: &Args) {
    let shown = render::clean(url);
    let as_browser = fetch_as(url, Some(BROWSER_UA))
        .unwrap_or_else(|e| die(&format!("couldn't download {shown} as a browser: {e}")));
    let curl_sha = soothsay::sha256::hex(as_curl);
    let browser_sha = soothsay::sha256::hex(&as_browser);
    if curl_sha == browser_sha {
        eprintln!(
            "soothsay: cloak check passed: {shown} sends curl and a browser the same bytes \
             (sha256 {})",
            &curl_sha[..12]
        );
        return;
    }
    eprintln!(
        "\nsoothsay: WARNING: the server sends a different script to curl than to a browser.\n\
         \x20 as curl:    sha256 {curl_sha}\n\
         \x20 as browser: sha256 {browser_sha}\n\
         What you'd read in a browser is not what `curl | sh` would run. Below is what \
         changes (browser → curl)."
    );
    let browser_report = if guard::not_a_script(&as_browser).is_some() {
        soothsay::analyze("")
    } else {
        soothsay::analyze_bytes(&as_browser)
    };
    let d = soothsay::diff::compare(&browser_report, &soothsay::analyze_bytes(as_curl));
    let browser_name = format!("{shown} (as browser)");
    let curl_name = format!("{shown} (as curl)");
    if args.json {
        print!("{}", soothsay::diff::json(&d, &browser_name, &curl_name));
    } else {
        print!(
            "{}",
            soothsay::diff::text(&d, &browser_name, &curl_name, args.color)
        );
    }
    process::exit(1);
}

/// Read at most one byte past [`MAX_INPUT`], so oversize input is detected
/// without buffering all of it.
fn read_capped(r: impl Read) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    r.take(MAX_INPUT + 1).read_to_end(&mut buf)?;
    Ok(buf)
}

/// The script's exit status, or 128+N if signal N killed it, as shells report it.
fn exit_code(s: process::ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = s.signal() {
            return 128 + sig;
        }
    }
    s.code().unwrap_or(1)
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

fn check(command: &str, cwd: PathBuf, can_ask: bool) -> Decision {
    let home = home();
    let Some(cache) = guard::default_cache(home.as_deref()) else {
        return Decision::Block(
            "soothsay: no cache directory (set SOOTHSAY_CACHE or HOME); blocking to be safe".into(),
        );
    };
    let g = Guard {
        cwd,
        home,
        cache,
        fetch: &fetch,
        can_ask,
    };
    g.check(command)
}

/// Download a script with the user's `curl`, the same client a `curl | sh`
/// would have used, so a server that cloaks by user agent serves us the same
/// bytes.
fn fetch(url: &str) -> Result<Vec<u8>, String> {
    fetch_as(url, None)
}

/// [`fetch`], optionally sending a different User-Agent than curl's own.
fn fetch_as(url: &str, user_agent: Option<&str>) -> Result<Vec<u8>, String> {
    let mut cmd = process::Command::new("curl");
    cmd.args([
        "-fsSL",
        "--proto",
        "=https,http",
        "--connect-timeout",
        "10",
        "--max-time",
        "30",
        "--max-filesize",
        "16777216",
    ]);
    if let Some(ua) = user_agent {
        cmd.args(["-A", ua]);
    }
    let mut child = cmd
        .args(["--", url])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("running curl: {e}"))?;
    let mut body = Vec::new();
    if let Some(out) = child.stdout.take() {
        out.take(MAX_INPUT + 1)
            .read_to_end(&mut body)
            .map_err(|e| format!("reading curl output: {e}"))?;
    }
    let mut err = String::new();
    if let Some(e) = child.stderr.take() {
        let _ = e.take(4096).read_to_string(&mut err);
    }
    let status = child.wait().map_err(|e| format!("waiting for curl: {e}"))?;
    if !status.success() {
        let why = err.lines().next().unwrap_or("").trim();
        return Err(format!(
            "curl exited with {}{}{why}",
            exit_code(status),
            if why.is_empty() { "" } else { ": " }
        ));
    }
    Ok(body)
}

/// `soothsay hook`: a Claude Code PreToolUse hook. Exit 0 lets the command
/// through; exit 2 blocks it and hands stderr to Claude. Every failure,
/// including a panic, blocks: any other exit code would let the command run.
fn hook() -> ! {
    std::panic::set_hook(Box::new(|info| {
        eprintln!("soothsay hook crashed ({info}); blocking this command to be safe.");
        process::exit(2);
    }));
    let block = |msg: &str| -> ! {
        eprintln!("{msg}");
        process::exit(2);
    };
    let mut input = String::new();
    if let Err(e) = io::stdin().take(4 * 1024 * 1024).read_to_string(&mut input) {
        block(&format!(
            "soothsay hook: reading input: {e}; blocking to be safe"
        ));
    }
    let v = json::parse(&input).unwrap_or_else(|e| {
        block(&format!(
            "soothsay hook: input isn't valid JSON ({e}); blocking to be safe"
        ))
    });
    if v.get("tool_name").and_then(json::Value::as_str) != Some("Bash") {
        process::exit(0);
    }
    let Some(command) = v
        .get("tool_input")
        .and_then(|t| t.get("command"))
        .and_then(json::Value::as_str)
    else {
        block("soothsay hook: Bash call without a command string; blocking to be safe");
    };
    let cwd = v
        .get("cwd")
        .and_then(json::Value::as_str)
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| block("soothsay hook: no working directory; blocking to be safe"));
    // Only modes that really stop and prompt the user can carry an "ask";
    // anywhere else (or if the mode is unknown) a run of reviewed bytes blocks.
    let can_ask = matches!(
        v.get("permission_mode").and_then(json::Value::as_str),
        Some("default" | "acceptEdits" | "plan")
    );
    match check(command, cwd, can_ask) {
        Decision::Pass => process::exit(0),
        Decision::Block(msg) => block(&msg),
        Decision::Ask(msg) => {
            println!(
                "{{\"hookSpecificOutput\":{{\"hookEventName\":\"PreToolUse\",\
                 \"permissionDecision\":\"ask\",\"permissionDecisionReason\":{}}}}}",
                render::json_str(&msg)
            );
            process::exit(0);
        }
    }
}
