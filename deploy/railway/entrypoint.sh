#!/bin/sh
# Container entrypoint for the Railway image. Idempotent: prepares the volume,
# seeds the config once, then runs `hn <args>` as the service user.
#
#   HN_DATA_DIR / HN_CONFIG_DIR   default under the volume (/data/hn/…)
#   HN_PORT                       defaults to Railway's PORT
#   HN_EXAMPLES_DIR               where the config/*.example.json live (image: /app/config)
set -eu

export HN_DATA_DIR="${HN_DATA_DIR:-/data/hn/data}"
export HN_CONFIG_DIR="${HN_CONFIG_DIR:-/data/hn/config}"
export HN_BIND="${HN_BIND:-0.0.0.0}"
export HN_PORT="${HN_PORT:-${PORT:-8080}}"
EXAMPLES="${HN_EXAMPLES_DIR:-/app/config}"
SVC_USER="${HN_USER:-hn}"

mkdir -p "$HN_DATA_DIR" "$HN_CONFIG_DIR"

# First boot: an empty config dir gets each config/<name>.example.json as
# <name>.json. A file that already exists is never touched (the server
# hot-reloads these; edit them on the volume).
for ex in "$EXAMPLES"/*.example.json; do
  [ -e "$ex" ] || continue
  target="$HN_CONFIG_DIR/$(basename "$ex" .example.json).json"
  if [ ! -e "$target" ]; then
    cp "$ex" "$target"
    echo "[hn-entrypoint] seeded $target from $(basename "$ex") — edit it for this deployment" >&2
  fi
done

# The volume mounts root-owned; the service user must own its files (the
# 0600 issuer key and accounts.json are written by it). Drop privileges.
if [ "$(id -u)" = 0 ]; then
  chown -R "$SVC_USER:$SVC_USER" "$HN_DATA_DIR" "$HN_CONFIG_DIR"
  chmod 700 "$HN_DATA_DIR"
  exec setpriv --reuid="$SVC_USER" --regid="$SVC_USER" --init-groups hn "$@"
fi
exec hn "$@"
