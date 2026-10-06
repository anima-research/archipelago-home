#!/usr/bin/env bash
# Provision a dedicated Archipelago identity box (id.animalabs.ai).
# Run as root on a fresh Ubuntu LTS VPS. Idempotent. Does NOT copy secrets or
# data and does NOT touch DNS: those are separate, deliberate steps.
#
#   ADMIN_USER   existing sudo user that keeps SSH access (default: ubuntu)
#   SSH_PUBLIC   "public" (keys only, open to the internet) or "tailnet" (port 22 only on tailscale0)
set -euo pipefail
ADMIN_USER=${ADMIN_USER:-ubuntu}
SSH_PUBLIC=${SSH_PUBLIC:-public}
APP_DIR=/opt/archipelago-home
SVC_USER=hn

log() { printf '\n== %s\n' "$*"; }

log "packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get -yq upgrade
apt-get install -yq nginx certbot python3-certbot-nginx ufw unattended-upgrades unzip curl ca-certificates age rclone

log "automatic security updates, with a reboot window (04:30 UTC)"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
cat > /etc/apt/apt.conf.d/52identity-reboot <<'EOF'
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:30";
EOF
systemctl enable --now unattended-upgrades

log "SSH: keys only, no root, few pending logins per address"
# 00- sorts before the cloud image's 50-cloud-init.conf; sshd keeps the FIRST value it reads.
cat > /etc/ssh/sshd_config.d/00-identity-hardening.conf <<EOF
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 20
PerSourceMaxStartups 3
AllowUsers ${ADMIN_USER}
EOF
sshd -t
# Socket-activated sshd (Ubuntu 22.10+) reads its config per start; reload only if a daemon is running.
systemctl try-reload-or-restart ssh.service 2>/dev/null || systemctl try-reload-or-restart sshd.service 2>/dev/null || true

log "firewall: web in, everything else closed"
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp
ufw allow 443/tcp
if [ "$SSH_PUBLIC" = "tailnet" ] && ip link show tailscale0 >/dev/null 2>&1; then
  ufw allow in on tailscale0 to any port 22 proto tcp
  ufw delete allow 22/tcp >/dev/null 2>&1 || true
else
  ufw allow 22/tcp
fi
ufw --force enable

log "service user and Bun"
id -u "$SVC_USER" >/dev/null 2>&1 || useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin "$SVC_USER"
mkdir -p "$APP_DIR"
if [ ! -x /usr/local/bin/bun ]; then
  curl -fsSL https://bun.sh/install | BUN_INSTALL=/usr/local/bun bash -s "bun-v1.3.14"
  ln -sf /usr/local/bun/bin/bun /usr/local/bin/bun
fi
bun --version

log "systemd unit (sandboxed: writes only to data/ and config/)"
cat > /etc/systemd/system/archipelago-home.service <<EOF
[Unit]
Description=archipelago-home identity node (id.animalabs.ai)
After=network-online.target
Wants=network-online.target

[Service]
User=${SVC_USER}
WorkingDirectory=${APP_DIR}
EnvironmentFile=${APP_DIR}/.env
ExecStart=/usr/local/bin/bun src/cli.ts serve
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
ReadWritePaths=${APP_DIR}/data ${APP_DIR}/config
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

log "nginx vhost (TLS added by certbot or by copying the current certificate)"
cat > /etc/nginx/sites-available/id.animalabs.ai <<'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name id.animalabs.ai;
    client_max_body_size 64k;
    location / {
        proxy_pass http://127.0.0.1:7360;
        proxy_set_header Host $host;
        # Overwritten here, so the app can trust it for per-client rate limits.
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF
ln -sf /etc/nginx/sites-available/id.animalabs.ai /etc/nginx/sites-enabled/id.animalabs.ai
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

log "done — next: copy code/data/secrets, start the service, TLS, test, DNS"
