# Security policy

soothsay sits between people and scripts they're about to run, so a bug that makes
it *look* safe when it isn't is a security bug, not an accuracy nit.

## Reporting a vulnerability

Please report privately through GitHub's
[private vulnerability reporting](https://github.com/rijuld/soothsay/security/advisories/new)
(**Security → Report a vulnerability** on the repo). Don't open a public issue for
anything in the list below until a fix is out.

Include a minimal script that reproduces it, the soothsay version (`soothsay -V`),
and what you expected to see. You should get a reply within a week. Fixes ship as a
patch release, and the advisory credits you unless you'd rather it didn't.

## What counts as a security bug

- **Clean verdict for a hostile script.** A script that downloads and runs code,
  exfiltrates secrets, installs persistence, opens a reverse shell (anything in a
  `danger`/`warn` category) gets "Clear skies" / "Mild omens", or passes
  `--fail-on` / `--deny`. That includes hiding findings by making them look
  unreachable.
- **Output injection.** Script content that reaches your terminal as control
  characters (ANSI escapes, cursor movement, bidi overrides) and can hide or rewrite
  the report, or that breaks the structure of `--json`.
- **Crashes and hangs on input.** A panic, stack overflow or super-linear blow-up
  caused by a script. In CI or an agent hook these can turn into a silent pass.
- **`--run` executing something other than what was analyzed.** Different bytes
  from the ones hashed and reported, a re-download, a temp file another user can
  swap, or a hash in the prompt that doesn't match the bytes.

A rule that misses some ordinary installer behaviour, or flags something harmless,
is an accuracy bug: please use the *"Misread an installer"* issue template instead.

## Threat model

soothsay is **advisory static analysis, not a sandbox.**

- It reads a script and never runs it, except with `--run` after you confirm.
- A determined author can always build behaviour at runtime that no static reader
  can see. soothsay's job is to report those constructs (`eval` of dynamic
  strings, decoded payloads, downloaded binaries, sourced files) as blind spots
  rather than stay quiet. "No findings" is not a guarantee.
- Code it points at but can't read (downloaded binaries, inline Python/Ruby, files
  fetched at runtime) is out of scope for analysis but in scope for reporting.
- The supported way to rely on it automatically (CI, agent hooks) is to fail
  closed. Treat any exit code other than `0` as "don't run".

## Supported versions

Only the latest release gets security fixes.
