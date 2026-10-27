#!/usr/bin/env bash
# Encrypted offsite backup of the identity node (id.animalabs.ai).
#
# Packs data/ (signing key, principals, invites, accounts — password hashes,
# TOTP secrets, passkey keys — and the mint log), config/, .env,
# history/ and the nginx vhost into one tar, compresses it and encrypts it with
# age to the public keys in $CONF/recipients.txt, then uploads it to S3.
# Plaintext exists only inside the pipe; nothing unencrypted is written to disk.
# This box holds only public keys, so it cannot read its own backups.
#
#   $CONF/recipients.txt   age or ssh-ed25519 public keys, one per line
#   $CONF/rclone.conf      rclone remote for the bucket (root 0600)
#   REMOTE                 destination prefix (default ovh:connbackups/identity)
#   KEEP_DAILY             daily copies to keep (default 30); one per month is kept forever
#
# Restore (on a machine holding a matching private key):
#   rclone copyto ovh:connbackups/identity/daily/<name> ./<name>
#   age -d -i ~/.ssh/id_ed25519 <name> | zstd -d | tar -xf - -C <restore-dir>
#   (inside: opt/archipelago-home/{data,config,.env,history}, etc/nginx/..., MANIFEST.sha256)
set -euo pipefail
umask 077

CONF=${CONF:-/etc/identity-backup}
APP=${APP:-/opt/archipelago-home}
REMOTE=${REMOTE:-ovh:connbackups/identity}
KEEP_DAILY=${KEEP_DAILY:-30}
STATE=${STATE:-/var/lib/identity-backup}
export RCLONE_CONFIG=$CONF/rclone.conf

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }

[ -s "$CONF/recipients.txt" ] || { log "no recipients in $CONF/recipients.txt"; exit 1; }
[ -s "$RCLONE_CONFIG" ] || { log "no rclone config at $RCLONE_CONFIG"; exit 1; }
[ -s "$APP/data/issuer-key.pem" ] || { log "no signing key at $APP/data/issuer-key.pem — refusing to back up an incomplete node"; exit 1; }

stamp=${STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}   # STAMP: tests only
month=${stamp:0:6}
name="identity-$stamp.tar.zst.age"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Paths relative to / so a restore lands where the service expects them.
paths=(
  "${APP#/}/data"
  "${APP#/}/config"
  "${APP#/}/.env"
)
[ -d "$APP/history" ] && paths+=("${APP#/}/history")
[ -f /etc/nginx/sites-available/id.animalabs.ai ] && paths+=(etc/nginx/sites-available/id.animalabs.ai)

# Checksums travel inside the encrypted tar, so a restore can be verified.
( cd / && find "${paths[@]}" -type f -print0 | sort -z | xargs -0 sha256sum ) > "$work/MANIFEST.sha256"
files=$(wc -l < "$work/MANIFEST.sha256")

tar --numeric-owner -cf - -C / "${paths[@]}" -C "$work" MANIFEST.sha256 \
  | zstd -q -19 \
  | age -R "$CONF/recipients.txt" -o "$work/$name"
rm -f "$work/MANIFEST.sha256"

size=$(stat -c %s "$work/$name")
head -c 21 "$work/$name" | grep -q '^age-encryption.org/v1' || { log "output is not an age file"; exit 1; }

rclone copyto "$work/$name" "$REMOTE/daily/$name"
rclone lsf "$REMOTE/daily/$name" | grep -qx "$name" || { log "upload not visible at $REMOTE/daily/$name"; exit 1; }
log "uploaded $name ($size bytes, $files files)"

# One copy per month, never pruned.
if ! rclone lsf "$REMOTE/monthly/" 2>/dev/null | grep -q "^identity-$month"; then
  rclone copyto "$work/$name" "$REMOTE/monthly/$name"
  log "monthly copy $name"
fi

# Prune daily/ to the newest KEEP_DAILY, touching only names this script writes.
mapfile -t daily < <(rclone lsf "$REMOTE/daily/" | grep -E '^identity-[0-9]{8}T[0-9]{6}Z\.tar\.zst\.age$' | sort)
excess=$(( ${#daily[@]} - KEEP_DAILY ))
if [ "$excess" -gt 0 ]; then
  for old in "${daily[@]:0:$excess}"; do
    rclone deletefile "$REMOTE/daily/$old"
    log "pruned $old"
  done
fi

mkdir -p "$STATE"
printf '%s %s %s\n' "$stamp" "$name" "$size" > "$STATE/last-success"
