#!/usr/bin/env bash
# Encrypted offsite backup of the identity node (id.animalabs.ai).
#
# Packs data/ (signing key, principals, invites, accounts — password hashes,
# TOTP secrets, passkey keys — and the mint log), config/, .env,
# history/ and the nginx vhost into one tar, compresses it and encrypts it with
# age to the public keys in $CONF/recipients.txt, then uploads it to S3.
# Plaintext exists only in RAM (a snapshot under /run, removed on exit) and
# inside the pipe; nothing unencrypted is written to disk.
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
trap 'rm -rf "$work"' EXIT   # widened to the snapshot below

# Paths relative to / so a restore lands where the service expects them.
paths=(
  "${APP#/}/data"
  "${APP#/}/config"
  "${APP#/}/.env"
)
[ -d "$APP/history" ] && paths+=("${APP#/}/history")
[ -f /etc/nginx/sites-available/id.animalabs.ai ] && paths+=(etc/nginx/sites-available/id.animalabs.ai)

# Plaintext lives only in RAM: a snapshot under the unit's RuntimeDirectory
# (/run/identity-backup, tmpfs), removed on exit; SNAPSHOT_DIR names another
# RAM-backed directory for a manual run. /run must hold one copy of data/.
ram=${SNAPSHOT_DIR:-${RUNTIME_DIRECTORY:-}}
[ -n "$ram" ] && [ -d "$ram" ] || { log "no RAM directory for the snapshot — run via the systemd unit, or set SNAPSHOT_DIR"; exit 1; }
snap="$ram/snap.$$"
trap 'rm -rf "$work" "$snap"' EXIT

# Writers' tmp files (renamed into place) and lock files are in-flight
# scaffolding, never state: neither copied nor archived. The mint log is
# copied apart (step 1b), so it isn't in the state check either.
MINT_LOG="${APP#/}/data/minted.jsonl"
skip=(--exclude='*.tmp' --exclude='*.lock' --exclude="$MINT_LOG")
live_hashes() {
  ( cd / && find "${paths[@]}" -type f ! -name '*.tmp' ! -name '*.lock' ! -path "$MINT_LOG" -print0 \
      | sort -z | xargs -0 sha256sum )
}

# 1a. A stable snapshot of the state files. The service keeps running and
# writing: an enrollment rewrites principals.json and invites.json together,
# sign-ins update accounts.json. So: hash the live files, copy them into RAM,
# hash again. Equal hashes mean nothing changed while the copy was made, so
# the snapshot is one moment's view — never half an enrollment. These files
# are small and rarely written, so the window is milliseconds; a retry backs
# off (1, 2, 4, 8 s) to outlast a burst. GNU tar exits 1 when a file changes
# under it ("file changed as we read it"): the same retry case. Any other
# copy failure (e.g. /run full) fails the run.
stable=
for attempt in 1 2 3 4 5; do
  rm -rf "$snap"
  mkdir -p "$snap"
  if before=$(live_hashes); then
    set +e
    tar --numeric-owner "${skip[@]}" -cf - -C / "${paths[@]}" | tar --numeric-owner -xpf - -C "$snap"
    st=("${PIPESTATUS[@]}")
    set -e
    [ "${st[1]}" -eq 0 ] || { log "snapshot copy failed (tar -x exit ${st[1]}) — is $ram full?"; exit 1; }
    case "${st[0]}" in
      0) [ "$(live_hashes 2>/dev/null)" = "$before" ] && { stable=1; break; } ;;
      1) ;; # a file changed while tar read it
      *) log "snapshot read failed (tar exit ${st[0]})"; exit 1 ;;
    esac
  fi
  [ "$attempt" -lt 5 ] || break
  log "state files changed while taking the snapshot (attempt $attempt) — again in $((1 << (attempt - 1)))s"
  sleep $((1 << (attempt - 1)))
done
[ -n "$stable" ] || { log "state files kept changing across 5 attempts — no consistent snapshot, nothing uploaded"; exit 1; }

# 1b. The mint log is append-only and never read at runtime (an audit
# trail), so it needs no agreement with the state files, only whole lines:
# take the lines complete at one instant. Lines already written never
# change, so `head -n` of that count is exact even while appends go on.
if [ -f "/$MINT_LOG" ]; then
  size=$(stat -c %s "/$MINT_LOG")
  lines=0
  [ "$size" -gt 0 ] && lines=$(head -c "$size" "/$MINT_LOG" | LC_ALL=C tr -dc '\n' | wc -c)
  if [ "$lines" -gt 0 ]; then head -n "$lines" "/$MINT_LOG" > "$snap/$MINT_LOG"; else : > "$snap/$MINT_LOG"; fi
fi

# 2. Hash and archive that same view. Nothing writes to the snapshot, so the
# manifest inside the archive is exactly what the archive holds.
( cd "$snap" && find "${paths[@]}" -type f -print0 | sort -z | xargs -0 sha256sum ) > "$work/MANIFEST.sha256"
files=$(wc -l < "$work/MANIFEST.sha256")
tar --numeric-owner -cf - -C "$snap" "${paths[@]}" -C "$work" MANIFEST.sha256 \
  | zstd -q -19 \
  | age -R "$CONF/recipients.txt" -o "$work/$name"
rm -rf "$snap" "$work/MANIFEST.sha256"

size=$(stat -c %s "$work/$name")
head -c 21 "$work/$name" | grep -q '^age-encryption.org/v1' || { log "output is not an age file"; exit 1; }

rclone copyto "$work/$name" "$REMOTE/daily/$name"
rclone lsf "$REMOTE/daily/$name" | grep -qx "$name" || { log "upload not visible at $REMOTE/daily/$name"; exit 1; }
log "uploaded $name ($size bytes, $files files)"

# A listing that fails fails the run, instead of reading as "empty": an
# unreadable monthly/ must not look like "no copy this month yet", nor an
# unreadable daily/ like "nothing to prune". The one exception is rclone's
# exit 3, "directory not found" — a prefix nothing has been written under
# yet (monthly/ before the first monthly copy), which really is empty.
list() {
  local out rc=0
  out=$(rclone lsf "$1") || rc=$?
  # (runs inside $(…): its log goes to stderr, or it would land in the variable)
  [ "$rc" -eq 0 ] || [ "$rc" -eq 3 ] || { log "listing $1 failed (rclone exit $rc) — not pruning or copying on a guess" >&2; exit 1; }
  printf '%s' "$out"
}

# One copy per month, never pruned.
monthly=$(list "$REMOTE/monthly/")
if ! printf '%s\n' "$monthly" | grep -q "^identity-$month"; then
  rclone copyto "$work/$name" "$REMOTE/monthly/$name"
  log "monthly copy $name"
fi

# Prune daily/ to the newest KEEP_DAILY, touching only names this script writes.
listing=$(list "$REMOTE/daily/")
daily=$(printf '%s\n' "$listing" | grep -E '^identity-[0-9]{8}T[0-9]{6}Z\.tar\.zst\.age$' | sort || true)
count=$(printf '%s' "$daily" | grep -c . || true)
excess=$(( count - KEEP_DAILY ))
if [ "$excess" -gt 0 ]; then
  printf '%s\n' "$daily" | head -n "$excess" | while read -r old; do
    rclone deletefile "$REMOTE/daily/$old"
    log "pruned $old"
  done
fi

mkdir -p "$STATE"
printf '%s %s %s\n' "$stamp" "$name" "$size" > "$STATE/last-success"
