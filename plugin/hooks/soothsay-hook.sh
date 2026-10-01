#!/bin/sh
# Runs `soothsay hook` for Claude Code's PreToolUse event.
#
# The plugin can't ship the binary, so look for it. If it's missing (or too old
# to have `hook`), don't stall every command: block only the ones that look like
# they run downloaded code, and say how to install it. Exit 2 is the only code
# that blocks, so that's the one used.

for b in "${SOOTHSAY_BIN:-}" "$(command -v soothsay 2>/dev/null)" \
    "$HOME/.cargo/bin/soothsay" /opt/homebrew/bin/soothsay /usr/local/bin/soothsay; do
    if [ -n "$b" ] && [ -x "$b" ] && "$b" --help 2>/dev/null | grep -q 'soothsay hook'; then
        exec "$b" hook
    fi
done

input=$(cat)
if printf '%s' "$input" | grep -Eq 'curl|wget|aria2c|<\(|\| *(sudo +)?(ba|z|da|k)?sh'; then
    echo "soothsay plugin: the soothsay binary isn't installed (or is too old to have" \
        "'soothsay hook'), so this command can't be reviewed. Blocking it to be safe." \
        "Ask the user to install it: https://github.com/rijuld/soothsay/releases/latest (or cargo install --locked --git https://github.com/rijuld/soothsay --tag v0.1.0)" >&2
    exit 2
fi
exit 0
