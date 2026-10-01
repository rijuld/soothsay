# Contributing to soothsay

Thanks for helping people read the omens. 🔮

## The most valuable contribution: real installers

soothsay's quality depends on how well it reads *real* scripts. If you run it on an
installer you use and it:

- **misses something** the script clearly does, or
- **cries wolf** about something harmless,

please open an issue using the *"Misread an installer"* template. Include the URL, the
line, and what you expected. A reduced snippet that reproduces it is gold.

## Codebase tour

Everything is in `src/`, seven files with zero dependencies:

| File | What it does |
| --- | --- |
| `lexer.rs` | Shell tokenizer: quotes, `$(…)`, `${x:-y}`, heredocs, redirects. Never panics, never gives up. |
| `parse.rs` | Tokens → simple commands, with pipeline ids, function scopes and `case` arms. |
| `analyze.rs` | The rules. `Analyzer::dispatch` is a big `match` on the command name. Start there. |
| `render.rs` | Terminal and JSON output. |
| `sha256.rs` | A tiny SHA-256 so reports can pin exact bytes. |
| `main.rs` | CLI flags, policy exit codes and `--run`. |
| `lib.rs` | The library entry point: `soothsay::analyze()` and re-exports. |

The flow for each command is:

1. `head()` strips assignments and prefixes (`sudo`, `env`, `nohup`, wrapper functions)
   and resolves variables.
2. `redirects()` handles `>`, `>>`, heredocs and here-strings.
3. `dispatch()` matches the command name and calls `add()` with a category, severity and
   message, or `write()` for anything that touches a path.

## Adding a rule

1. Write a failing test in `tests/analyze.rs`:

   ```rust
   #[test]
   fn detects_my_thing() {
       assert_has(&analyze("some command --flag"), Category::Security, Severity::Warn, "what it says");
   }
   ```

2. Add a `match` arm in `Analyzer::dispatch` (or extend `classify()` for new path kinds).
3. Pick the severity honestly:
   - **danger**: almost never legitimate in an installer (exfiltration, reverse shells,
     disabling Gatekeeper).
   - **warn**: legitimate sometimes, but you'd want to know before it happens
     (persistence, nested `curl | sh`, `/etc` writes).
   - **notice**: normal installer behaviour worth listing (profile edits, `sudo`).
   - **info**: bookkeeping, hidden unless `-v`.
4. Run the checks CI runs (CI also builds on the MSRV, Rust 1.74, so avoid newer
   std APIs):

   ```sh
   cargo fmt --check
   cargo clippy --locked --all-targets -- -D warnings
   cargo test --locked
   ```

## Bypasses and robustness

- **Every bypass gets a regression test.** If you fix a way for a hostile script to
  get a clean verdict, add the smallest script that reproduced it as a test in the
  test file for that area under `tests/` (lexing, parsing/reachability, rules,
  rendering, CLI), and assert the finding *and* its severity.
- **A crash or a hang is a bug, not an edge case.** If some input makes soothsay
  panic, overflow the stack or take seconds instead of milliseconds, that's a way to
  make CI or an agent hook fail open. Add the input (or a generator for it) to the
  tests.
- Security-relevant bypasses go through [SECURITY.md](SECURITY.md), not a public issue.

## Ground rules

- **No new dependencies** without a very good reason. Auditability is a feature.
- **Test fixtures are synthetic.** Please don't commit third-party install scripts
  (licensing, and they change). Reduce the pattern to a few lines instead.
- **Messages are for humans.** Say what happens ("appends to ~/.zshrc"), not what the
  code is ("RedirectAppend(ShellProfile)").
- The lexer must never panic. `never_panics_on_garbage` should grow whenever you touch it.

## Releasing

Maintainers only: bump `version` in `Cargo.toml`, tag `vX.Y.Z`, and publish.
