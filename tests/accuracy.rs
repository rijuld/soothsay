//! Patterns from real installers that soothsay used to misread. Each script
//! here is a synthetic reduction; no third-party installer is committed.

use soothsay::{analyze, Category, Finding, Report, Severity};

fn live(r: &Report) -> Vec<&Finding> {
    r.findings.iter().filter(|f| f.reachable).collect()
}

fn find<'a>(r: &'a Report, needle: &str) -> Option<&'a Finding> {
    live(r).into_iter().find(|f| f.message.contains(needle))
}

fn assert_has<'a>(r: &'a Report, cat: Category, sev: Severity, needle: &str) -> &'a Finding {
    live(r)
        .into_iter()
        .find(|f| f.category == cat && f.severity >= sev && f.message.contains(needle))
        .unwrap_or_else(|| {
            panic!(
                "expected {cat:?} >= {sev:?} containing {needle:?}:\n{:#?}",
                live(r)
            )
        })
}

/// get.docker.com: `sh_c` is `sh -c`, `sudo -E sh -c` or `su -c` (or `echo`
/// for a dry run), and every privileged step is `$sh_c "…"`.
const DOCKER_SH_C: &str = r#"#!/bin/sh
user="$(id -un 2>/dev/null || true)"
sh_c='sh -c'
if [ "$user" != 'root' ]; then
	if command_exists sudo; then
		sh_c='sudo -E sh -c'
	elif command_exists su; then
		sh_c='su -c'
	fi
fi
if is_dry_run; then
	sh_c="echo"
fi
$sh_c "install -m 0755 -d /etc/apt/keyrings"
$sh_c "curl -fsSL https://download.example.com/gpg -o /etc/apt/keyrings/docker.asc"
$sh_c "echo 'deb [signed-by=/etc/apt/keyrings/docker.asc] https://download.example.com stable' > /etc/apt/sources.list.d/docker.list"
$sh_c "systemctl enable --now docker.service"
"#;

#[test]
fn sh_c_variable_runs_its_code_as_root() {
    let r = analyze(DOCKER_SH_C);
    let w = assert_has(
        &r,
        Category::System,
        Severity::Warn,
        "/etc/apt/sources.list.d/docker.list",
    );
    assert!(w.as_root, "{w:?}");
    assert!(assert_has(&r, Category::System, Severity::Warn, "/etc/apt/keyrings").as_root);
    assert_has(
        &r,
        Category::Persistence,
        Severity::Warn,
        "enables a systemd service",
    );
    assert_eq!(r.max_severity(), Some(Severity::Warn));
    // The code is read, not reported as an opaque script.
    assert!(find(&r, "runs the script").is_none(), "{:#?}", live(&r));
}

#[test]
fn single_valued_runner_and_plain_sudo_sh_c() {
    for src in [
        "SH_C=\"sudo sh -c\"\n$SH_C \"echo x > /etc/foo.conf\"\n",
        "SH_C='doas bash -c'\n$SH_C 'echo x > /etc/foo.conf'\n",
        "sudo sh -c 'echo x > /etc/foo.conf'\n",
        "SUDO=sudo\n$SUDO sh -c 'echo x > /etc/foo.conf'\n",
    ] {
        let r = analyze(src);
        let f = assert_has(&r, Category::System, Severity::Warn, "/etc/foo.conf");
        assert!(f.as_root, "{src}: {f:?}");
    }
    // Without sudo, the same code isn't root.
    let r = analyze("sh_c='sh -c'\n$sh_c 'echo x > /etc/foo.conf'\n");
    assert!(!assert_has(&r, Category::System, Severity::Warn, "/etc/foo.conf").as_root);
}

#[test]
fn quoted_or_unrelated_variables_are_not_runners() {
    // A quoted "$sh_c" is one word (`sudo sh -c` as a program name), so the shell
    // never runs the code: don't report its effects as happening.
    let r = analyze("sh_c='sudo sh -c'\n\"$sh_c\" 'echo x > /etc/foo.conf'\n");
    assert!(
        !live(&r).iter().any(|f| f.category == Category::System),
        "{:#?}",
        live(&r)
    );
    // A variable that's just a program isn't a shell runner.
    let r = analyze("TAR='tar -xzf'\n$TAR x.tgz\n");
    assert!(find(&r, "runs the script").is_none());
}

#[test]
fn deleting_under_a_function_argument_is_not_a_warning() {
    // get.pnpm.io: `rm -rf "$dir/unpacked"` where dir is the function's `$3`.
    let r = analyze("unpack() {\n  rm -rf \"$3/unpacked\"\n}\nunpack a b /tmp/x\n");
    let f = find(&r, "rm -r on ${3}/unpacked").expect("still listed");
    assert_eq!(f.severity, Severity::Info, "{f:?}");
}

#[test]
fn deleting_under_a_checked_or_always_set_variable_is_not_a_warning() {
    // ohmyzsh: ZDOTDIR is only used after `[ -n "$ZDOTDIR" ]`.
    let r = analyze(
        "if [ -n \"$ZDOTDIR\" ] && [ \"$ZDOTDIR\" != \"$HOME\" ]; then\n  rm -rf \"$ZDOTDIR/ohmyzsh\"\nfi\n",
    );
    assert_eq!(
        find(&r, "${ZDOTDIR}/ohmyzsh").unwrap().severity,
        Severity::Info
    );
    // k3s: BIN_DIR is always assigned something.
    let r = analyze("BIN_DIR=/usr/local/bin\nrm -rf \"${BIN_DIR}/k3s-ro-test\"\n");
    // (`map_or` rather than `is_none_or`: the crate supports Rust 1.74.)
    assert!(find(&r, "if $BIN_DIR is ever empty").map_or(true, |f| f.severity == Severity::Info));
}

#[test]
fn genuinely_risky_deletes_still_warn() {
    for src in [
        // Never assigned: empty means `rm -rf /*`.
        "rm -rf \"$TARGET_DIR/\"*\n",
        // A function argument deleted bare: empty means `/`.
        "clean() {\n  rm -rf \"$1/\"\n}\nclean \"$X\"\n",
        // Assigned, but sometimes to nothing.
        "DIR=\"\"\nif x; then DIR=/opt/app; fi\nrm -rf \"$DIR/lib\"\n",
        // Top-level positional argument.
        "rm -rf \"$1/build\"\n",
    ] {
        let r = analyze(src);
        assert!(
            live(&r)
                .iter()
                .any(|f| f.category == Category::Destructive && f.severity >= Severity::Warn),
            "{src}: {:#?}",
            live(&r)
        );
    }
}

/// Homebrew's `have_sudo_access`: `"${SUDO[@]}" -v` and `-l mkdir` only check
/// whether sudo works.
#[test]
fn sudo_access_checks_are_not_commands() {
    let src = r#"have_sudo_access() {
  local -a SUDO=("/usr/bin/sudo")
  if [[ -n "${NONINTERACTIVE-}" ]]; then
    SUDO+=("-n")
  fi
  if ! /usr/bin/sudo -n -v 2>/dev/null; then
    trap '/usr/bin/sudo -k' EXIT
  fi
  "${SUDO[@]}" -v && "${SUDO[@]}" -l mkdir &>/dev/null
}
have_sudo_access
sudo -K
sudo -ll
"#;
    let r = analyze(src);
    let roots: Vec<_> = live(&r)
        .into_iter()
        .filter(|f| f.category == Category::Privilege)
        .collect();
    assert!(roots.is_empty(), "{roots:#?}");
}

#[test]
fn sudo_flags_that_still_run_a_command() {
    for (src, needle) in [
        ("sudo -n mkdir -p /opt/app\n", "mkdir -p /opt/app"),
        ("sudo -k rm -rf /opt/app\n", "rm -rf /opt/app"),
        (
            "SUDO=(sudo -A)\n\"${SUDO[@]}\" mkdir -p /opt/app\n",
            "mkdir -p /opt/app",
        ),
        (
            "sudo -E -u root chown x /usr/local/bin\n",
            "chown x /usr/local/bin",
        ),
    ] {
        let r = analyze(src);
        let f = live(&r)
            .into_iter()
            .find(|f| f.category == Category::Privilege)
            .unwrap_or_else(|| panic!("{src}: no root finding"));
        assert!(f.message.ends_with(needle), "{src}: {}", f.message);
    }
}
