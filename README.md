<div align="center">

# 🔮 soothsay

**Read the omens before you `curl | sh`.**

`soothsay` reads a shell install script and tells you, in plain English, what it's
about to do to your machine *before* you run it.

![license: MIT](https://img.shields.io/badge/license-MIT-blue)
![dependencies: 0](https://img.shields.io/badge/dependencies-0-brightgreen)
![rust: 1.74+](https://img.shields.io/badge/rust-1.74%2B-orange)

```sh
curl -fsSL https://example.com/install.sh | soothsay
```

</div>

---

## Why this exists

In 2026 almost every developer tool installs the same way:

```sh
curl -fsSL https://<some-ai-cli>.dev/install.sh | bash
```

Coding agents, runtimes, package managers and language toolchains all do it. You're
handing a stranger's 2,000-line shell script a root-capable terminal. You'll get a nice
progress bar, but you won't be told that it:

- appended three lines to your `~/.zshrc`,
- installed a `launchd` job that runs at every login,
- used `sudo` 41 times,
- downloaded a *second* script and piped that into `sh` too,
- stripped macOS quarantine so Gatekeeper never looks at the binary.

Reading the script yourself is the right answer, and nobody does it. `soothsay` does it
for you in about a millisecond and hands you the parts that matter.

## What it looks like

This is real output for Bun's installer (`curl -fsSL https://bun.sh/install | soothsay`),
captured on 2026-09-28:

```text
🔮 soothsay  stdin · 326 lines · bash · sha256 04882bf4…3be8

  ● EDITS YOUR SHELL STARTUP FILES
    L214   ● appends to ~/.config/fish/config.fish
    L246   ● appends to ~/.zshrc
    L293   ● appends to ${bash_config} (looks like your shell profile)

  ● BLIND SPOTS: SOOTHSAY CAN'T SEE PAST THESE
    L177   ● runs ~/.bun/bin/bun: a program soothsay can't see inside (also L197, L229, L261)
           ↳ ~/.bun/bin/bun completions

  FILES IT TOUCHES
    ~/.bun/bin                  create
    ~/.bun/bin/bun.zip          download, delete
    ~/.bun/bin/bun              copy
    ~/.bun/bin/bun-${target}    delete
    ~/.config/fish/config.fish  append
    ~/.zshrc                    append
    ${bash_config}              append

  URLS
    download ${bun_uri}

  🌤  Mild omens. Typical installer behaviour; skim the notices.
     7 notices
     2 low-level notes hidden (use -v)
     soothsay reads scripts; it doesn't run them. Advisory, not a sandbox.
```

That's a well-behaved installer. Here's an excerpt of the report for
[`tests/fixtures/nasty.sh`](tests/fixtures/nasty.sh), a deliberately hostile test script:

```text
🔮 soothsay  nasty.sh · 39 lines · sh · sha256 d67d5b29…ffe6

  ▲ RUNS MORE CODE FROM THE INTERNET
    L9     ▲ pipes http://updates.example.net/stage2.sh straight into bash as root
    L10    ▲ downloads and runs https://example.net/stage3.sh with sh
    L11    ▲ downloads and runs https://example.net/env.sh with source

  ✖ HIDDEN OR ENCODED PAYLOADS
    L14    ✖ decodes a hidden payload and pipes it into sh
           ↳ base64 --decode

  ✖ TOUCHES SECRETS & CREDENTIALS
    L26    ✖ reads ~/.ssh/id_ed25519 and sends it over the network
           ↳ cat ~/.ssh/id_ed25519
    L27    ✖ appends to ~/.ssh/authorized_keys: adds keys that can log into this machine
           ↳ ssh-ed25519 AAAA attacker@box
    L28    ✖ shows a fake dialog asking for your password
           ↳ osascript -e display dialog "macOS needs your password" default answer "" with hidden answer
    L29    ✖ reads the macOS Keychain (find-generic-password)
    L24    ▲ reads ~/.ssh
           ↳ tar czf /tmp/k.tgz ~/.ssh ~/.aws/credentials
    L24    ▲ reads ~/.aws/credentials
           ↳ tar czf /tmp/k.tgz ~/.ssh ~/.aws/credentials

  ✖ WEAKENS SECURITY SETTINGS
    L5     ✖ stops recording shell history
    L33    ✖ turns Gatekeeper off for the whole machine
    L34    ✖ sets setuid/setgid on /usr/local/lib/helper/run: it will run with its owner's privileges
    L36    ✖ redirects into a raw network socket /dev/tcp/10.0.0.1/4444 (classic reverse shell)
    L32    ▲ strips macOS quarantine so Gatekeeper won't check the download
           ↳ xattr -dr com.apple.quarantine /Applications/Helper.app

  … (persistence, deletes, root, system writes, network, files and URLs sections cut for length)

  ☠️  Dark omens. Don't run this unless you understand every red line.
     9 dangers · 12 warnings · 8 notices
```

## Install

```sh
git clone https://github.com/rijuld/soothsay && cd soothsay
cargo install --path .
```

It's a single ~570 KB binary with **zero dependencies**. That's on purpose: a tool you
pipe untrusted scripts into should be small enough to audit in an afternoon. The whole
thing is about 3,000 lines of plain Rust. (It isn't on crates.io yet; publishing it is
on the [roadmap](#roadmap).)

## Usage

```sh
# Pipe a script in
curl -fsSL https://example.com/install.sh | soothsay

# Or point it at a file
soothsay ./install.sh

# Everything, including low-level notes and uncapped lists
soothsay -v install.sh

# Read the report, then decide, then run *exactly the bytes you just read*
curl -fsSL https://sh.rustup.rs | soothsay --run -- -y
```

### `--run`: review, then run the bytes you reviewed

`--run` prints the report and asks on your terminal (`/dev/tty`, since stdin is the script):

```text
Run these exact bytes (sha256 7d0ea0f8eba7…) with sh? [y/N]
```

If you say yes, it writes the **buffered, already-analyzed bytes** to a private temp file
(`0700`) and runs that. It never re-downloads. That matters because a server can detect
`curl | sh` and [serve different content to a pipe than to a browser](https://www.idontplaydarts.com/2016/04/detecting-curl-pipe-bash-server-side/).
The script gets your terminal as stdin, so installers that prompt still work, and
soothsay exits with the script's exit code.

### In CI: guard your own installer

If you maintain an `install.sh`, soothsay can keep it honest across PRs:

```yaml
# .github/workflows/installer.yml
- run: cargo install --git https://github.com/rijuld/soothsay
- run: soothsay --deny persistence,remote-exec,obfuscation --fail-on danger install.sh
```

| Flag | Effect |
| --- | --- |
| `--deny <cats>` | exit `1` if any live finding is in these categories (comma-separated, or `all`) |
| `--fail-on <sev>` | exit `1` if any live finding is at least `notice` / `warn` / `danger` |
| `--json` | machine-readable report (findings, files, URLs, functions, sha256) |
| `--run [-y]` | run the analyzed bytes after confirming (or with `-y`, without asking) |
| `--shell <sh>` | interpreter for `--run` (default: the shebang, else `sh`) |
| `--no-color` | plain output (also honours `NO_COLOR`; colour is off when piped) |

Exit codes: `0` ok · `1` policy matched · `2` usage or I/O error.

## What it detects

```text
$ soothsay --categories
remote-exec  pipes a download into a shell, or evals/sources remote content
obfuscation  decodes base64/hex and executes it, or carries large encoded blobs
secrets      reads or uploads SSH keys, cloud credentials, keychains, browser data
security     setuid, world-writable files, Gatekeeper bypass, sudoers, reverse shells
destructive  rm -rf, dd, mkfs, and deletes that go wrong when a variable is empty
persistence  cron, launchd, systemd, login items: anything that runs again later
rc-edit      appends to ~/.zshrc, ~/.bashrc, ~/.profile, fish config, /etc/paths.d
privilege    sudo, doas, pkexec, su
system       writes to /usr, /etc, /opt, /Library and friends
packages     apt, brew, dnf, pip, npm -g, cargo install ...
config       defaults write, git config --global, network settings
network      what it downloads, uploads, and whether TLS is checked
blind-spot   eval of dynamic strings, running downloaded binaries, sourcing files
```

Severities: **danger** (✖) · **warn** (▲) · **notice** (●) · **info** (·, hidden unless `-v`).

### What popular installers do

This is a neutral snapshot, not a ranking. Most of what installers do is exactly what
you asked for; the point is to *know*. Counts are live findings at notice level or
above, from scripts fetched on 2026-09-28.

| Installer | Lines | Highest | What stands out |
| --- | ---: | --- | --- |
| Bun | 326 | notice | edits 3 shell profiles; runs the binary it installed |
| Claude Code | 260 | notice | hands off to the downloaded `claude install` binary |
| Deno | 116 | notice | runs the installed `deno` to finish setup |
| nvm | 495 | notice | appends 2 lines to the profile `nvm_detect_profile` picks |
| rustup | 930 | notice | the real work happens inside `rustup-init`, a blind spot |
| uv | 2,191 | notice | edits shell profiles via `$_rcfile` |
| Homebrew | 1,236 | warn | 26 `sudo` calls; overwrites `/etc/paths.d/homebrew` |
| Ollama (Linux path) | 455 | warn | creates a system user, installs & enables a systemd service, writes apt sources |

Notice how often the answer is "then it runs a binary." That's the honest limit of
reading a script, and soothsay says so instead of guessing.

## How it works

```
 script bytes ──► lexer ──► parser ──► analyzer ──► report
                   │          │           │
                   │          │           ├─ resolves variables:  INSTALL_DIR="${X:-$HOME/.zap}" → ~/.zap
                   │          │           ├─ follows $PROFILE across case branches → "one of ~/.zshrc, ~/.bashrc…"
                   │          │           ├─ sees through wrappers: ensure / ignore / execute_sudo "$@"
                   │          │           ├─ recurses into $(…), <(…), sh -c '…', eval '…', heredocs fed to sh
                   │          │           └─ marks code in never-called functions as unreachable
                   │          └─ simple commands + pipelines + function scopes + case arms
                   └─ quotes, $'…', ${x:-y}, ${!ref}, $(…), `…`, <(…), heredocs, 2>&1, [[ … && … ]]
```

- **A real tokenizer, not regexes.** `echo "rm -rf /"` is a string, `# curl | sh` is a
  comment, and a heredoc body written to a file is data. None of those are reported.
  ([`tests/fixtures/tricky.sh`](tests/fixtures/tricky.sh) checks this.)
- **Reachability.** Installers define lots of functions. A `sudo rm -rf /` inside a
  function nothing calls is shown dimmed, not counted.
- **Blind spots are findings.** When a script runs a binary it just downloaded, evals a
  runtime string, or sources a file, soothsay tells you it can't see past that point.
- **It never runs anything** unless you pass `--run` and confirm.

### As a library

```rust
let report = soothsay::analyze(script);
for f in report.findings.iter().filter(|f| f.reachable) {
    println!("{:?} line {}: {}", f.severity, f.line, f.message);
}
```

## Limitations (please read)

- **It is advisory static analysis, not a sandbox.** A determined attacker can hide
  intent from any static reader, for example by building a command out of fragments
  at runtime. soothsay reports those constructs (`eval`, decoded payloads, dynamic
  program names) as blind spots, but "no findings" is not a guarantee.
- It reads POSIX sh, bash and most zsh installer syntax. It doesn't evaluate
  arithmetic, loops or conditionals, so a variable set on several branches is shown as
  all its possible values or as `${NAME}`.
- It doesn't analyze non-shell code (inline Python/Ruby, downloaded binaries); it only
  points at it.

## Prior art

- [`vet`](https://github.com/vet-run/vet) and [`shed`](https://pypi.org/project/shed_sh/)
  show you the script (and a diff since last time) before running it. soothsay
  *summarizes behaviour* instead: it answers "what will this do?" rather than "here's the
  text".
- [ShellCheck](https://www.shellcheck.net/) finds bugs in shell scripts. soothsay finds
  *effects*. They complement each other.

## Contributing

Contributions are very welcome, especially **real-world false positives and misses**.
If soothsay misreads an installer you use, that's a bug. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the codebase tour (it's four files) and how to add
a rule with a test.

### Roadmap

Good first issues are marked 🌱.

- 🌱 More persistence locations (XDG autostart variants, `~/.config/fish/functions`, shell
  `precmd` hooks)
- 🌱 Detect `git config --global` credential helpers and `npm config set registry`
  (supply-chain redirects)
- 🌱 A `--markdown` renderer for pasting reports into PRs
- 🌱 Shell completions
- `--diff old.sh new.sh`: what *changed* in an installer's behaviour between versions
- Follow `curl … -o x.sh; sh x.sh` within the same script (analyze the file it runs when
  its URL is known)
- A small constant-propagation pass so `for f in a b; do … "$f"` resolves
- Publish to crates.io and ship prebuilt binaries

## License

MIT. See [LICENSE](LICENSE).
