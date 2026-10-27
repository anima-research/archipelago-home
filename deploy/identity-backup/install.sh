#!/usr/bin/env bash
# Install the identity backup on the identity box. Run as root from this directory.
# Needs, beforehand: /etc/identity-backup/recipients.txt (public keys only) and
# /etc/identity-backup/rclone.conf (root 0600). This script does not create either.
set -euo pipefail
cd "$(dirname "$0")"
install -d -m 0700 /etc/identity-backup
[ -s /etc/identity-backup/recipients.txt ] || { echo "missing /etc/identity-backup/recipients.txt"; exit 1; }
[ -s /etc/identity-backup/rclone.conf ] || { echo "missing /etc/identity-backup/rclone.conf"; exit 1; }
chmod 0600 /etc/identity-backup/rclone.conf
# Every tool the job pipes through — without one, each nightly run would fail
# while this install looked fine.
for tool in age rclone zstd tar sha256sum cmp; do
  command -v "$tool" >/dev/null || { echo "missing $tool — apt-get install -y $tool (zstd, age, rclone are packages of those names)"; exit 1; }
done
install -m 0755 identity-backup.sh /usr/local/sbin/identity-backup.sh
install -m 0644 identity-backup.service identity-backup.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now identity-backup.timer
systemctl list-timers identity-backup.timer --no-pager
