use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::process::{self, Stdio};

use soothsay::{render, Category, Severity};

const HELP: &str = "\
soothsay: read the omens before you `curl | sh`

USAGE
    curl -fsSL https://example.com/install.sh | soothsay [OPTIONS]
    soothsay [OPTIONS] install.sh

    Reads a shell script and tells you what it will do to your machine before
    you run it: files written, shell profiles edited, sudo, startup items,
    nested downloads, hidden payloads, credential access.

OPTIONS
    -v, --verbose          Show low-level notes and every item (no truncation)
        --json             Machine-readable report on stdout
        --run              After the report, ask on your terminal, then run the
                           *exact bytes* that were analyzed (never re-downloads)
    -y, --yes              With --run: don't ask (policy flags still apply)
        --shell <SH>       Interpreter for --run (default: the script's shebang, else sh)
        --deny <CATS>      Exit 1 if any finding is in these categories
                           (comma-separated ids, or \"all\")
        --fail-on <SEV>    Exit 1 if any finding is at least this severe
                           (notice | warn | danger)
        --ignore-unreachable
                           Let --deny / --fail-on skip findings in functions
                           that look never-called (off by default: a script
                           can hide how it calls them)
        --categories       List category ids and exit
        --no-color         Disable colour (also honours NO_COLOR)
    -h, --help             Show this help
    -V, --version          Show version

    Arguments after `--` are passed to the script by --run:
        curl -fsSL https://sh.rustup.rs | soothsay --run -- -y

EXIT STATUS
    0  report printed (and, with --run, the script's own exit status)
    1  a --deny / --fail-on policy matched
    2  usage or I/O error
";

struct Args {
    file: Option<String>,
    json: bool,
    verbose: bool,
    run: bool,
    yes: bool,
    shell: Option<String>,
    deny: Vec<Category>,
    fail_on: Option<Severity>,
    ignore_unreachable: bool,
    color: bool,
    script_args: Vec<String>,
}

fn die(msg: &str) -> ! {
    eprintln!("soothsay: {msg}");
    process::exit(2);
}

fn parse_args() -> Args {
    let mut a = Args {
        file: None,
        json: false,
        verbose: false,
        run: false,
        yes: false,
        shell: None,
        deny: Vec::new(),
        fail_on: None,
        ignore_unreachable: false,
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
            "--shell" => a.shell = Some(value("--shell")),
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
    let args = parse_args();

    let (source, bytes) = match args.file.as_deref() {
        None | Some("-") => {
            if io::stdin().is_terminal() {
                eprint!("{HELP}");
                process::exit(2);
            }
            let mut buf = Vec::new();
            io::stdin()
                .read_to_end(&mut buf)
                .unwrap_or_else(|e| die(&format!("reading stdin: {e}")));
            ("stdin".to_string(), buf)
        }
        Some(path) => {
            let buf = fs::read(path).unwrap_or_else(|e| die(&format!("{path}: {e}")));
            (path.rsplit('/').next().unwrap_or(path).to_string(), buf)
        }
    };
    let src = String::from_utf8_lossy(&bytes);
    let report = soothsay::analyze(&src);

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
        let shell = args.shell.clone().unwrap_or_else(|| {
            let i = report.interpreter.as_str();
            if matches!(i, "sh" | "bash" | "zsh" | "dash" | "ksh") {
                i.to_string()
            } else {
                "sh".into()
            }
        });
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
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => {
            eprintln!("soothsay: running {shell}: {e}");
            2
        }
    }
}
