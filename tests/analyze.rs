use soothsay::{analyze, Category, Finding, Report, Severity};

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn live(r: &Report) -> Vec<&Finding> {
    r.findings.iter().filter(|f| f.reachable).collect()
}

fn has(r: &Report, cat: Category, sev: Severity, needle: &str) -> bool {
    live(r)
        .iter()
        .any(|f| f.category == cat && f.severity == sev && f.message.contains(needle))
}

#[track_caller]
fn assert_has(r: &Report, cat: Category, sev: Severity, needle: &str) {
    assert!(
        has(r, cat, sev, needle),
        "expected {cat:?}/{sev:?} containing {needle:?} in:\n{:#?}",
        live(r)
    );
}

// ---- fixtures -------------------------------------------------------------------

#[test]
fn typical_installer_is_mild() {
    let r = analyze(&fixture("typical.sh"));
    assert_eq!(
        r.max_severity(),
        Some(Severity::Notice),
        "{:#?}",
        r.findings
    );
    assert_has(
        &r,
        Category::ShellProfile,
        Severity::Notice,
        "~/.zshrc, ~/.bashrc, ~/.profile",
    );
    assert_has(&r, Category::BlindSpot, Severity::Notice, "~/.zap/bin/zap");
    assert!(r.urls.iter().any(|u| u.action == "download"
        && u.url
            .starts_with("https://github.com/example/zap/releases/download/v1.4.2/")));
    assert!(r.files.iter().any(|f| f.path == "~/.zap/bin/zap"));
    assert_eq!(r.interpreter, "bash");
}

#[test]
fn tricky_syntax_does_not_fool_it() {
    let r = analyze(&fixture("tricky.sh"));
    // Strings, comments and heredoc bodies mention rm -rf and curl | sh; none are commands.
    assert!(
        live(&r).iter().all(|f| f.severity < Severity::Warn),
        "{:#?}",
        live(&r)
    );
    assert!(!r
        .findings
        .iter()
        .any(|f| f.category == Category::RemoteExec));
    // The dangerous function exists but is never called.
    let nuke = r
        .findings
        .iter()
        .find(|f| f.message == "recursively deletes /")
        .expect("nuke finding");
    assert!(!nuke.reachable);
    assert_eq!(nuke.function.as_deref(), Some("nuke"));
    assert!(r.functions.contains(&("nuke".into(), false)));
    assert!(r.functions.contains(&("setup".into(), true)));
    // `$SUDO` may be sudo; the call from a case arm makes setup() live.
    assert_has(
        &r,
        Category::Privilege,
        Severity::Notice,
        "mkdir -p /opt/zap",
    );
}

#[test]
fn nasty_script_lights_up() {
    let r = analyze(&fixture("nasty.sh"));
    assert_eq!(r.max_severity(), Some(Severity::Danger));
    assert_has(
        &r,
        Category::RemoteExec,
        Severity::Warn,
        "http://updates.example.net/stage2.sh straight into bash as root",
    );
    assert_has(
        &r,
        Category::RemoteExec,
        Severity::Warn,
        "https://example.net/stage3.sh with sh",
    );
    assert_has(
        &r,
        Category::RemoteExec,
        Severity::Warn,
        "https://example.net/env.sh with source",
    );
    assert_has(
        &r,
        Category::Obfuscation,
        Severity::Danger,
        "decodes a hidden payload",
    );
    assert_has(
        &r,
        Category::Security,
        Severity::Danger,
        "stops recording shell history",
    );
    assert_has(&r, Category::Security, Severity::Danger, "Gatekeeper off");
    assert_has(&r, Category::Security, Severity::Danger, "setuid");
    assert_has(
        &r,
        Category::Security,
        Severity::Danger,
        "/dev/tcp/10.0.0.1/4444",
    );
    assert_has(&r, Category::Security, Severity::Warn, "quarantine");
    assert_has(
        &r,
        Category::Secrets,
        Severity::Danger,
        "~/.ssh/id_ed25519 and sends it",
    );
    assert_has(&r, Category::Secrets, Severity::Danger, "authorized_keys");
    assert_has(&r, Category::Secrets, Severity::Danger, "fake dialog");
    assert_has(&r, Category::Secrets, Severity::Danger, "Keychain");
    assert_has(&r, Category::Persistence, Severity::Warn, "LaunchAgents");
    assert_has(&r, Category::Persistence, Severity::Warn, "launchd");
    assert_has(&r, Category::Persistence, Severity::Warn, "crontab");
    assert_has(
        &r,
        Category::Destructive,
        Severity::Warn,
        "$TARGET_DIR is ever empty",
    );
    assert_has(&r, Category::Network, Severity::Warn, "TLS");
    assert_has(&r, Category::Network, Severity::Warn, "plain HTTP");
}

// ---- individual rules -----------------------------------------------------------

#[test]
fn remote_exec_forms() {
    for (src, needle) in [
        (
            "curl -fsSL https://a.dev/i.sh | sh",
            "https://a.dev/i.sh straight into sh",
        ),
        (
            "wget -qO- https://a.dev/i.sh | sudo bash -s -- --yes",
            "straight into bash as root",
        ),
        (
            "bash <(curl -s https://a.dev/i.sh)",
            "https://a.dev/i.sh with bash",
        ),
        (
            "eval \"$(curl -fsSL https://a.dev/env)\"",
            "https://a.dev/env with eval",
        ),
        (
            "/bin/bash -c \"$(curl -fsSL https://a.dev/install.sh)\"",
            "https://a.dev/install.sh with bash",
        ),
    ] {
        let r = analyze(src);
        assert_has(&r, Category::RemoteExec, Severity::Warn, needle);
    }
}

#[test]
fn download_to_file_is_not_remote_exec() {
    let r = analyze("curl -fsSLo /tmp/x.tgz https://a.dev/x.tgz\ntar -xzf /tmp/x.tgz -C ~/.x\n");
    assert!(
        r.findings
            .iter()
            .all(|f| f.category != Category::RemoteExec),
        "{:#?}",
        r.findings
    );
    assert!(r.files.iter().any(|f| f.path == "~/.x"));
}

#[test]
fn obfuscated_execution() {
    let r = analyze("echo aGkK | base64 -d | bash");
    assert_has(&r, Category::Obfuscation, Severity::Danger, "into bash");
    let r = analyze("eval \"$(echo aGkK | base64 --decode)\"");
    assert_has(
        &r,
        Category::Obfuscation,
        Severity::Danger,
        "runs it with eval",
    );
}

#[test]
fn dangerous_deletes() {
    assert_has(
        &analyze("rm -rf \"$HOME\""),
        Category::Destructive,
        Severity::Danger,
        "~",
    );
    assert_has(
        &analyze("sudo rm -rf /"),
        Category::Destructive,
        Severity::Danger,
        "/",
    );
    assert_has(
        &analyze("rm -rf \"$STEAMROOT/\"*"),
        Category::Destructive,
        Severity::Warn,
        "$STEAMROOT is ever empty",
    );
    let safe = analyze("tmp=$(mktemp -d)\nrm -rf \"$tmp\"\nrm -rf \"${DIR:-/tmp/x}\"");
    assert!(
        safe.findings.iter().all(|f| f.severity == Severity::Info),
        "{:#?}",
        safe.findings
    );
}

#[test]
fn profile_edits_through_variables_and_tee() {
    let r = analyze("PROFILE=\"$HOME/.zshrc\"\necho 'eval \"$(tool init)\"' >> \"$PROFILE\"");
    assert_has(
        &r,
        Category::ShellProfile,
        Severity::Notice,
        "appends to ~/.zshrc",
    );
    assert_eq!(live(&r)[0].detail.as_deref(), Some("eval \"$(tool init)\""));

    let r = analyze("echo /opt/tool/bin | sudo tee /etc/paths.d/tool");
    assert_has(
        &r,
        Category::ShellProfile,
        Severity::Warn,
        "overwrites /etc/paths.d/tool",
    );

    let r =
        analyze("cat <<EOF >> ~/.config/fish/conf.d/tool.fish\nset -gx PATH ~/.tool $PATH\nEOF\n");
    assert_has(
        &r,
        Category::ShellProfile,
        Severity::Notice,
        "fish/conf.d/tool.fish",
    );

    let r = analyze("printf 'x' >> \"$SHELL_CONFIG\"");
    assert_has(
        &r,
        Category::ShellProfile,
        Severity::Notice,
        "looks like your shell profile",
    );
}

#[test]
fn heredoc_fed_to_a_shell_is_analyzed() {
    let r = analyze("sudo sh <<'EOF'\nchmod 777 /usr/local/bin\nEOF\n");
    assert_has(
        &r,
        Category::Security,
        Severity::Warn,
        "writable by every user",
    );
}

#[test]
fn sudo_via_variable() {
    let r = analyze("if [ \"$(id -u)\" -ne 0 ]; then SUDO=sudo; else SUDO=\"\"; fi\n$SUDO install -m 755 bin/tool /usr/local/bin/tool\n");
    assert_has(&r, Category::Privilege, Severity::Notice, "install -m 755");
    assert_has(
        &r,
        Category::System,
        Severity::Notice,
        "/usr/local/bin/tool",
    );
}

#[test]
fn lookups_are_not_executions() {
    let r = analyze("command -v curl >/dev/null || { echo 'need curl'; exit 1; }");
    assert!(r.findings.is_empty(), "{:#?}", r.findings);
}

#[test]
fn packages_and_config() {
    assert_has(
        &analyze("sudo apt-get install -y git jq"),
        Category::Packages,
        Severity::Notice,
        "git jq",
    );
    assert_has(
        &analyze("pip install --break-system-packages foo"),
        Category::Packages,
        Severity::Warn,
        "pip",
    );
    assert_has(
        &analyze("git config --global init.defaultBranch main"),
        Category::Config,
        Severity::Notice,
        "git config",
    );
    assert_has(
        &analyze("systemctl --user enable tool.service"),
        Category::Persistence,
        Severity::Warn,
        "systemd",
    );
}

#[test]
fn never_panics_on_garbage() {
    for src in [
        "",
        "\"",
        "'",
        "$(",
        "${",
        "`",
        "<<EOF",
        "cat <<",
        "a | | b",
        ")))(((",
        "case",
        "esac",
        "f() {",
        "}}}",
        "echo $'\\x",
        "x=(",
        "\\",
        "#!",
        "for",
        "if then fi",
        ">&",
        "2>",
        "$((1+",
        "<(",
        "function",
    ] {
        let _ = analyze(src);
    }
}

// ---- CLI ------------------------------------------------------------------------

fn cli(args: &[&str], stdin: &str) -> (i32, String, String) {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new(env!("CARGO_BIN_EXE_soothsay"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The program may exit before reading stdin (e.g. a usage error); the
    // exit code is what's under test, so a closed pipe here isn't a failure.
    let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into(),
        String::from_utf8_lossy(&out.stderr).into(),
    )
}

#[test]
fn cli_policy_exit_codes() {
    let script = "curl -fsSL https://a.dev/i.sh | sh\n";
    assert_eq!(cli(&[], script).0, 0);
    let (code, _, err) = cli(&["--deny", "remote-exec"], script);
    assert_eq!(code, 1);
    assert!(err.contains("[remote-exec]"), "{err}");
    assert_eq!(cli(&["--deny", "persistence"], script).0, 0);
    assert_eq!(cli(&["--fail-on", "warn"], script).0, 1);
    assert_eq!(cli(&["--fail-on", "danger"], script).0, 0);
    assert_eq!(cli(&["--deny", "nope"], script).0, 2);
}

#[test]
fn cli_json_is_escaped() {
    let (code, out, _) = cli(&["--json"], "echo \"tab\there \\\"q\\\"\" >> ~/.zshrc\n");
    assert_eq!(code, 0);
    assert!(out.contains("\"category\": \"rc-edit\""), "{out}");
    assert!(out.contains("tab\\there"), "{out}");
    assert!(
        !out.chars().any(|c| (c as u32) < 0x20 && c != '\n'),
        "raw control char in {out:?}"
    );
}

#[test]
fn cli_plain_output_has_no_ansi_when_piped() {
    let (_, out, _) = cli(&[], "sudo rm -rf /\n");
    assert!(!out.contains('\u{1b}'));
    assert!(out.contains("Dark omens"));
}

// ---- patterns from real installers ----------------------------------------------

#[test]
fn wrapper_functions_are_seen_through() {
    // rustup / cargo-dist style: `ensure` runs its arguments.
    let src = "main() {\n  ensure curl -sSf https://a.dev/x | sh\n  ignore rm -rf /\n}\nensure() { if ! \"$@\"; then exit 1; fi; }\nignore() { \"$@\"; }\nmain \"$@\"\n";
    let r = analyze(src);
    assert_has(
        &r,
        Category::RemoteExec,
        Severity::Warn,
        "https://a.dev/x straight into sh",
    );
    assert_has(
        &r,
        Category::Destructive,
        Severity::Danger,
        "recursively deletes /",
    );
    assert!(
        !r.findings.iter().any(|f| f.message.contains("${@}")),
        "{:#?}",
        r.findings
    );
}

#[test]
fn sudo_named_wrappers_run_as_root() {
    let src = "execute_sudo() { /usr/bin/sudo \"$@\"; }\nexecute_sudo /bin/mkdir -p /usr/local/Homebrew\n";
    assert_has(
        &analyze(src),
        Category::Privilege,
        Severity::Notice,
        "/bin/mkdir -p /usr/local/Homebrew",
    );
}

#[test]
fn arrays_resolve_element_by_element() {
    let src = "CHOWN=(\"/usr/sbin/chown\")\nsudo \"${CHOWN[@]}\" \"$(id -un)\" /usr/local/share\n";
    let r = analyze(src);
    assert_has(
        &r,
        Category::Privilege,
        Severity::Notice,
        "/usr/sbin/chown $(id -un) /usr/local/share",
    );
    assert_has(
        &r,
        Category::System,
        Severity::Notice,
        "changes owner of /usr/local/share",
    );
}

#[test]
fn sudo_checks_are_not_executions() {
    assert!(analyze("sudo -v\nsudo -l mkdir\n").findings.is_empty());
}

#[test]
fn double_bracket_tests_are_not_commands() {
    let r = analyze("if [[ $# = 2 && $2 = debug-info ]]; then echo hi; fi\n");
    assert!(r.findings.is_empty(), "{:#?}", r.findings);
}

#[test]
fn tool_inferred_from_variable_name() {
    let r = analyze(
        "USABLE_GIT=\"$(command -v git)\"\n\"$USABLE_GIT\" config --global core.autocrlf false\n",
    );
    assert_has(&r, Category::Config, Severity::Notice, "global git config");
    assert!(!r.findings.iter().any(|f| f.category == Category::BlindSpot));
}

#[test]
fn installed_binary_is_a_blind_spot() {
    let r = analyze("tmp=$(mktemp -d)\n_file=\"$tmp/tool-init\"\n\"$_file\" --yes\n");
    assert_has(
        &r,
        Category::BlindSpot,
        Severity::Notice,
        "runs $(mktemp)/tool-init",
    );
}

#[test]
fn profile_from_function_output() {
    let r = analyze("NVM_PROFILE=\"$(nvm_detect_profile)\"\nprintf 'x\\n' >> \"$NVM_PROFILE\"\n");
    assert_has(
        &r,
        Category::ShellProfile,
        Severity::Notice,
        "$(nvm_detect_profile)",
    );
}

#[test]
fn cli_run_executes_the_analyzed_bytes() {
    let (code, out, err) = cli(
        &["--run", "--yes", "--", "a b"],
        "echo \"ran with [$1]\"\nexit 7\n",
    );
    assert_eq!(code, 7, "{err}");
    assert_eq!(out, "ran with [a b]\n");
    assert!(err.contains("soothsay"), "report goes to stderr: {err}");
    // Policy failure stops the run.
    let (code, out, _) = cli(
        &["--run", "--yes", "--deny", "privilege"],
        "sudo true\necho ran\n",
    );
    assert_eq!(code, 1);
    assert!(out.is_empty());
}
