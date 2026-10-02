use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use soothsay::guard::{Decision, Guard};

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("soothsay-pkg-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn iso(secs_ago: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let t = now - secs_ago;
    // Civil date from days (Howard Hinnant), enough for test fixtures.
    let days = (t / 86_400) as i64;
    let s = t % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z",
        s / 3600,
        s / 60 % 60,
        s % 60
    )
}

const DAY: u64 = 86_400;

fn search(name: &str, version: &str, weekly: u64, released_ago: u64) -> String {
    format!(
        r#"{{"objects":[{{"downloads":{{"weekly":{weekly}}},"package":{{"name":"{name}","version":"{version}","date":"{}"}}}}]}}"#,
        iso(released_ago)
    )
}

fn range(first_download_ago_days: u64) -> String {
    let days: Vec<String> = (0..365u64)
        .rev()
        .map(|ago| {
            let day = &iso(ago * DAY + 1)[..10];
            let n = if ago <= first_download_ago_days { 5 } else { 0 };
            format!(r#"{{"downloads":{n},"day":"{day}"}}"#)
        })
        .collect();
    format!(r#"{{"downloads":[{}]}}"#, days.join(","))
}

/// A fake registry that counts every request.
struct Registry {
    calls: RefCell<Vec<String>>,
    offline: bool,
}

impl Registry {
    fn new() -> Self {
        Registry {
            calls: RefCell::new(Vec::new()),
            offline: false,
        }
    }

    fn get(&self, url: &str) -> Result<Vec<u8>, String> {
        self.calls.borrow_mut().push(url.to_string());
        if self.offline {
            return Err("curl exited with 6: Could not resolve host".into());
        }
        let not_found = Err("curl exited with 22: The requested URL returned error: 404".into());
        let body = match url {
            // Established and pinned: cowsay
            u if u.contains("search?text=cowsay&") => search("cowsay", "1.6.0", 900_000, 400 * DAY),
            "https://registry.npmjs.org/cowsay/1.6.0" => r#"{"name":"cowsay","version":"1.6.0","scripts":{"test":"x"}}"#.into(),
            "https://registry.npmjs.org/cowsay/latest" => r#"{"name":"cowsay","version":"1.6.0"}"#.into(),
            "https://registry.npmjs.org/cowsay/9.9.9" => return not_found,
            // Established, but the latest release is a few hours old.
            u if u.contains("search?text=hotpkg&") => search("hotpkg", "4.0.1", 2_000_000, 3 * 3600),
            "https://registry.npmjs.org/hotpkg/latest" => r#"{"name":"hotpkg","version":"4.0.1"}"#.into(),
            // Unlisted name: search finds other packages, range 404s.
            u if u.contains("search?text=") && (u.contains("expres&") || u.contains("nope-zz9&")) => {
                search("express", "5.0.0", 50_000_000, 300 * DAY)
            }
            u if u.contains("/downloads/range/last-year/expres") || u.contains("/downloads/range/last-year/nope-zz9") => {
                return not_found
            }
            // Brand new: listed, first downloads three days ago.
            u if u.contains("search?text=fresh-thing&") => search("fresh-thing", "0.0.1", 40, 3 * DAY),
            u if u.contains("/downloads/range/last-year/fresh-thing") => range(3),
            // Older but obscure: two years old, a handful of downloads.
            u if u.contains("search?text=quiet-tool&") => search("quiet-tool", "1.2.0", 12, 200 * DAY),
            u if u.contains("/downloads/range/last-year/quiet-tool") => range(400),
            // PyPI: ruff (established), reqeusts (missing typo).
            "https://pypi.org/rss/project/ruff/releases.xml" => format!(
                "<rss><channel><item><title>0.6.0</title><pubDate>Thu, 15 Aug 2024 12:34:28 GMT</pubDate></item>{}</channel></rss>",
                "<item><title>0.5.0</title><pubDate>Mon, 01 Jul 2024 00:00:00 GMT</pubDate></item>".repeat(45)
            ),
            "https://pypistats.org/api/packages/ruff/recent" => r#"{"data":{"last_week":75719877}}"#.into(),
            "https://pypi.org/rss/project/reqeusts/releases.xml" => return not_found,
            _ => return Err(format!("unexpected URL in test: {url}")),
        };
        Ok(body.into_bytes())
    }
}

fn check(dir: &Path, reg: &Registry, cmd: &str, can_ask: bool) -> Decision {
    let fetch = |u: &str| reg.get(u);
    Guard {
        cwd: dir.to_path_buf(),
        home: Some(dir.join("home")),
        cache: dir.join("cache"),
        fetch: &fetch,
        can_ask,
    }
    .check(cmd)
}

fn blocked(d: Decision) -> String {
    match d {
        Decision::Block(m) => m,
        other => panic!("expected a block, got {other:?}"),
    }
}

fn asked(d: Decision) -> String {
    match d {
        Decision::Ask(m) => m,
        other => panic!("expected an ask, got {other:?}"),
    }
}

#[test]
fn non_runner_commands_never_touch_the_network() {
    let d = scratch("quiet");
    let reg = Registry::new();
    for cmd in [
        "cargo test --locked",
        "git status && ls -la",
        "npm install && npm test",
        "npm run build",
        "uv sync && uv run pytest",
        "deno run main.ts",
        "echo npx -y cowsay",
        "pip install -r requirements.txt",
    ] {
        assert_eq!(check(&d, &reg, cmd, true), Decision::Pass, "{cmd}");
    }
    assert!(reg.calls.borrow().is_empty(), "{:?}", reg.calls.borrow());
}

#[test]
fn popular_pinned_package_passes_in_two_small_requests() {
    let d = scratch("pinned");
    let reg = Registry::new();
    assert_eq!(
        check(&d, &reg, "npx -y cowsay@1.6.0 hello", true),
        Decision::Pass
    );
    let calls = reg.calls.borrow().clone();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert!(
        calls
            .iter()
            .all(|u| !u.ends_with("registry.npmjs.org/cowsay")),
        "never the full packument: {calls:?}"
    );
    // The second run comes from the cache.
    assert_eq!(
        check(&d, &reg, "npx -y cowsay@1.6.0 hello", true),
        Decision::Pass
    );
    assert_eq!(reg.calls.borrow().len(), 2);
}

#[test]
fn established_pypi_tool_passes() {
    let d = scratch("ruff");
    let reg = Registry::new();
    assert_eq!(
        check(&d, &reg, "uvx ruff@0.6.0 check .", true),
        Decision::Pass
    );
    assert_eq!(reg.calls.borrow().len(), 2);
}

#[test]
fn missing_package_blocks() {
    let d = scratch("missing");
    let reg = Registry::new();
    let msg = blocked(check(&d, &reg, "npx -y nope-zz9", true));
    assert!(msg.contains("isn't on npm"), "{msg}");
    let msg = blocked(check(&d, &reg, "pipx run reqeusts", true));
    assert!(msg.contains("isn't on PyPI"), "{msg}");
    assert!(msg.contains("did you mean requests"), "{msg}");
}

#[test]
fn typosquat_blocks() {
    let d = scratch("typo");
    let reg = Registry::new();
    let msg = blocked(check(&d, &reg, "npx -y expres", true));
    assert!(msg.contains("did you mean express"), "{msg}");
}

#[test]
fn missing_version_blocks() {
    let d = scratch("version");
    let reg = Registry::new();
    let msg = blocked(check(&d, &reg, "npx cowsay@9.9.9", true));
    assert!(msg.contains("no version 9.9.9"), "{msg}");
}

#[test]
fn brand_new_package_blocks() {
    let d = scratch("new");
    let reg = Registry::new();
    let msg = blocked(check(&d, &reg, "bunx fresh-thing", true));
    assert!(msg.contains("first published"), "{msg}");
}

#[test]
fn fresh_release_asks() {
    let d = scratch("fresh");
    let reg = Registry::new();
    let msg = asked(check(&d, &reg, "npx -y hotpkg", true));
    assert!(msg.contains("released 3 hours ago"), "{msg}");
    // A session that never prompts gets a block instead.
    let msg = blocked(check(&d, &reg, "npx -y hotpkg", false));
    assert!(msg.contains("without asking"), "{msg}");
}

#[test]
fn obscure_package_asks() {
    let d = scratch("obscure");
    let reg = Registry::new();
    let msg = asked(check(&d, &reg, "pnpm dlx quiet-tool", true));
    assert!(msg.contains("downloads in the last week"), "{msg}");
}

#[test]
fn unreachable_registry_asks() {
    let d = scratch("offline");
    let reg = Registry {
        offline: true,
        ..Registry::new()
    };
    let msg = asked(check(&d, &reg, "npx -y cowsay@1.6.0", true));
    assert!(msg.contains("couldn't reach the npm registry"), "{msg}");
    let msg = asked(check(&d, &reg, "uvx ruff", true));
    assert!(msg.contains("couldn't reach PyPI"), "{msg}");
}

#[test]
fn runtime_package_names_and_urls_ask() {
    let d = scratch("dynamic");
    let reg = Registry::new();
    asked(check(&d, &reg, "npx -y \"$PKG\"", true));
    asked(check(&d, &reg, "npx github:someone/tool", true));
    asked(check(
        &d,
        &reg,
        "deno run -A https://example.com/mod.ts",
        true,
    ));
    assert!(reg.calls.borrow().is_empty());
}
