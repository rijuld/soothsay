#!/bin/bash
# Syntax that naive regex scanners get wrong. Nothing in here should be
# reported as dangerous except where marked.

# A comment that mentions rm -rf / and curl | sh must not count.
msg="use rm -rf / at your own risk"   # a string is not a command
echo "${#msg} characters, # not a comment"

# Heredoc bodies written to a file are data, not commands.
cat > "$HOME/.zap/README" <<'EOF'
To uninstall: rm -rf ~/.zap
Or pipe: curl https://example.com | sh
EOF

# Code in a function that is never called can't run.
nuke() {
  sudo rm -rf /
}

# `command -v` is a lookup, not an execution.
if command -v sudo >/dev/null 2>&1; then
  SUDO=sudo
else
  SUDO=""
fi

setup() {
  $SUDO mkdir -p /opt/zap # marked: runs as root, writes to /opt
}

case "$1" in
  --help|-h) echo "usage" ;;
  *) setup ;;
esac

printf $'done\n'
