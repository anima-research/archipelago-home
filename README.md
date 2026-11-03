# archipelago-home

Connectome home node v0 — identity issuance for humans (Discord OAuth + guild-role→scope, or the
home's own login: username + password + TOTP, and passkeys) and agents (ed25519 key-proof or
operator-minted tokens). Design: **connectome `docs/home-node.md`**
(the authoritative spec); doctrine: connectome `docs/archipelago.md`.

One credential everywhere: the `aid1` ed25519-signed token. Audiences (eidoverse-worlds,
orrery, …) verify **offline** against the issuer public key — this service is never a party to
any connection and can be down without breaking anything except new logins.

## Run

```sh
npm install && npm run typecheck && npm test

cp config/roles.example.json config/roles.json          # fill guild + role snowflakes
cp config/audiences.example.json config/audiences.json
cp config/invite-policy.example.json config/invite-policy.json      # optional: the sponsor console's policy (Anima's)
DISCORD_CLIENT_ID=… DISCORD_CLIENT_SECRET=… npm start   # binds 127.0.0.1:7360; TLS = fronting proxy
```

Env: `HN_DOMAIN` (default `id.animalabs.ai`), `HN_PUBLIC_URL`, `HN_BIND`, `HN_PORT`,
`HN_DATA_DIR`, `HN_CONFIG_DIR`, `HN_BOT_TOKEN` (optional; also re-checks Discord roles live
when a Discord-linked person signs in another way), `HN_CLIENT_IP_HEADER` (optional; a header
the fronting proxy overwrites with the client address, trusted from any peer — for a platform
whose proxy is not on loopback, e.g. `x-real-ip` on Railway; unset, `X-Real-IP` counts only from
loopback). First run generates `data/issuer-key.pem`
(0600) — **the** issuer key; guard it, never commit it. `data/accounts.json` (0600) holds
password hashes, TOTP secrets and passkey keys — back it up with the issuer key, and guard it
the same way.

Discord app setup: dev portal → OAuth2 → redirect URI `https://<HN_DOMAIN>/oauth/callback`.
Scopes requested at login: `identify guilds.members.read` (no bot).

## Human sign-in

`/login?audience=…` is a chooser: **Continue with Discord**, **username + password** (then a
TOTP code if they turned one on), or **passkey** (also offered as autofill in the username
field). Every path ends the same way — a 10-minute aid1 token in the audience's URL fragment —
so audiences change nothing. `?via=discord` skips the chooser.

People manage their own sign-in at **`/account`**: set a username + password (a Discord person
keeps their `human:discord:` sub), turn TOTP on (QR + ten single-use recovery codes), add or
remove passkeys, link Discord to a local account. The page's credential is its own login token,
so it is always a recent sign-in.

Accounts for people without Discord come from the operator — there is no open sign-up. Run
`hn user` as the service user (`sudo -u hn …` on the identity box; it refuses to run as root,
since a root-owned 0600 `accounts.json` would lock the service out):

```sh
hn user add alice --scopes worlds:join,worlds:spectate   # → one-time setup link (72h)
hn user ls                                                # who has what (no secrets)
hn user reset alice [--clear-2fa] [--clear-passkeys]      # → new setup link
hn user set alice --scopes worlds:join,orrery:use         # operator grant (Discord roles add on top)
hn user disable alice    hn user enable alice
```

Throttles: 5 wrong passwords lock that username for 15 minutes; 10 wrong codes lock its second
factor for 15 minutes; a sign-in ticket allows 5 code tries. Passkeys are never throttled by
these, so they remain a way in during a lockout.

## The deployment's policy (config/)

What the node knows about *your* services is configuration, hot-reloaded (edit, save, no
restart; a file that doesn't parse or validate is refused and the last good one stays):

| file | says |
|---|---|
| `audiences.json` | the services: login redirect, scopes a login must hold, API and MCPL endpoints (`/services`) |
| `roles.json` | Discord guild roles → scopes (only with Discord on) |
| `invite-policy.json` | the sponsor console: who may open it, which scopes a sponsor may pass to their agent, what every invite and every anchored invite carries, which audiences follow from which scopes |

`invite-policy.json` is optional — without it the console is off and says so. Anima's is
`config/invite-policy.example.json`; the format, in full, is at the top of `src/policy.ts`. In short:

```jsonc
{
  "console": { "requiredScopes": ["worlds:join"] },     // who may open the console and mint
  "primaryAudience": "eidoverse",                       // enrollment's first token is for this one
  "scopes": {                                           // roles: delegable · anchorGrantable · baseline · resident
    "worlds:join": ["delegable", "resident"],
    "docs:use":    ["delegable", "baseline", "resident"]
  },
  "audiences": [                                        // in order; an audience ending in * = every registered match
    { "audience": "eidoverse",  "always": true },
    { "audience": "music",      "when": ["music:*"] },
    { "audience": "body",       "anchored": true },
    { "audience": "clawblox-*", "when": ["clawblox:play"] }
  ]
}
```

A sponsor passes on (their scopes ∩ `delegable`) — never more than they hold — plus `baseline` on
every invite; an `id:anchor` holder also grants `anchorGrantable` outright, and an anchored invite
carries every `resident` scope. A scope the file doesn't mention is never granted through the
console.

## Operator CLI

```sh
hn fingerprint                                                     # issuer pubkey id
hn mint --name ferro --aud eidoverse --scopes worlds:join --ttl 72h  # manual guest admission
hn invite --scopes worlds:join --max-uses 1 --expires 72h            # self-enroll invite code
hn ls        hn revoke agent:ferro@guest        hn revoke-invite <code>
```

(dev: `node --import tsx src/cli.ts <cmd>`; installed: `hn` after `npm run build` — `bin/hn.js` runs `dist/src/cli.js`.)

## Deploying a second home node on Railway

An independent home node — its own issuer key, its own people and agents, its own domain —
packaged by the `Dockerfile` and `railway.toml` here. Everything that must outlive a deploy
lives on **one volume mounted at `/data`**: `HN_DATA_DIR=/data/hn/data` (issuer key,
`principals.json`, `accounts.json`, `invites.json`, `minted.jsonl`) and
`HN_CONFIG_DIR=/data/hn/config` (`audiences.json`, `roles.json`, `invite-policy.json`). The
image has no runtime npm dependencies; it runs the compiled `dist/` on node 22.

**1. Service.** In a Railway project: *New → GitHub repo → this repository* (Railway reads
`railway.toml`: Dockerfile build, healthcheck `/healthz`, restart on failure). Add the volume
and the variables below before the first deploy finishes — a deploy without the volume still
boots, but generates an issuer key that the next deploy loses.

**2. Volume.** Right-click the service → *Attach volume* (or *Settings → Volumes*), mount path
**`/data`**. One volume per service. The container starts as root only to create
`/data/hn/{data,config}` and hand them to the `hn` service user, then drops privileges
(`deploy/railway/entrypoint.sh`); the server and the CLI never run as root. If the deploy log
shows permission errors on `/data`, Railway's documented remedy for volumes is the service
variable `RAILWAY_RUN_UID=0` (the entrypoint still drops to `hn` after taking ownership).

**3. Variables** (service → *Variables*):

| variable | value |
|---|---|
| `HN_DOMAIN` | `<your domain>` — the token issuer (`iss`); audiences pin it, so choose it once |
| `HN_PUBLIC_URL` | `https://<your domain>` |
| `DISCORD_CLIENT_ID`, `DISCORD_CLIENT_SECRET` | optional; Discord login (app setup above, redirect URI `https://<your domain>/oauth/callback`). Without them: local accounts (`hn user add`) and passkeys only |
| `HN_BOT_TOKEN` | optional; server-side role lookup |

Set in the image already: `HN_BIND=0.0.0.0`, `PORT=8080` (the entrypoint takes Railway's
`PORT` as `HN_PORT`), `HN_DATA_DIR`, `HN_CONFIG_DIR`, and `HN_CLIENT_IP_HEADER=x-real-ip` —
Railway's edge overwrites `X-Real-IP` with the client address (the sibling docs service relies
on the same header), so the per-client rate limit on sign-in works instead of putting everyone
behind the edge into one bucket. Set it to an empty value if requests reach the node some other
way than through Railway's proxy.

**4. Domain.** Service → *Settings → Public Networking → + Custom Domain*, enter
`<your domain>`, target port **8080**. Railway gives a `CNAME` and a `TXT` record — add both at
the DNS provider (the `TXT` verifies ownership; with only the `CNAME` in place the domain
returns 404). Behind Cloudflare: proxied, SSL/TLS mode *Full* (not *Full (strict)*).
Certificate issuance usually follows within an hour of DNS updating.

**5. First boot.** The deploy log shows `[hn-entrypoint] seeded …/config/audiences.json` (and
`roles.json`, `invite-policy.json`) — the `config/*.example.json` copied onto the empty
volume, once; an existing file is never overwritten — then
`[hn] home node for <your domain> on 0.0.0.0:8080 — issuer ed25519:…`. Check from outside:

```sh
curl https://<your domain>/.well-known/mcpl-identity   # {"scheme":"ed25519","domain":"<your domain>","publicKey":"ed25519:…"} — this node's new key
curl https://<your domain>/healthz                     # {"ok":true,"principals":0}
```

That `publicKey` is what every audience of this node pins (`DOCS_ISSUERS=<your domain>=ed25519:…`
on a docs service, and so on). It was generated on the volume; redeploys keep it.

**6. Operating `hn`.** The CLI runs **inside** the container, against the volume:

```sh
railway ssh -s <service>                      # a shell in the running container
railway ssh -s <service> hn fingerprint       # or one command; `railway ssh --help` for the rest
hn user add alice --scopes worlds:join        # → setup link on https://<your domain>
hn invite --scopes worlds:join --max-uses 1 --expires 72h
hn ls
```

`hn` there is `deploy/railway/hn`: the ssh shell is root, and `hn user` refuses to run as root
(a root-owned 0600 `accounts.json` would lock the service out), so the wrapper re-executes as
the `hn` service user first. `railway run <cmd>` and `railway shell` run **on your machine**
with the service's variables injected — they do not see the volume; an `hn` there would mint
against a local `data/` dir and a different key.

**7. Audiences and policy.** Edit the files on the volume; the server re-reads each within
3 s (mtime poll) and logs `[hn] audiences: reloaded`, or refuses a file that does not parse or
validate and keeps the last good one — check the log after an edit. The slim image has no
editor, so write the file whole from the ssh shell:

```sh
railway ssh -s <service>
cat > /data/hn/config/audiences.json <<'EOF'
{
  "docs": { "redirect": "https://docs.<your domain>/auth", "requiredScopes": ["docs:use"] }
}
EOF
cat /data/hn/config/audiences.json   # read it back
```

`roles.json` matters only with Discord login on. `invite-policy.json` as seeded is the example
policy, which turns the sponsor console on for `worlds:join` holders — rewrite it for your
services, or remove it and **restart the service** to turn the console off: a removed file is
not hot-reloaded, only a changed one. There is no `hn config` command.

**8. Backups.** Service → *Settings → Backups*: schedules are daily (kept 6 days), weekly
(27 days), monthly (89 days); several can be on at once; a restore mounts the backup as a new
volume for review before deploy. Turn at least one on — the issuer key and `accounts.json`
(password hashes, TOTP secrets, passkeys) exist nowhere else. For an off-platform copy, copy
`/data/hn` out of the container through `railway ssh` (the key and `accounts.json` are 0600 and
belong to `hn`; the ssh shell is root, so it can read them — handle the copy as the secrets they
are). A redeploy of a service with a volume has a short downtime (one deployment is mounted at a time).

## Audience integration

```ts
import { verifyToken, JtiCache, resolveIssuerKey } from '@animalabs/archipelago-home/verifier';
```

Contract (spec §5): verify signature/iss/aud/exp/scopes offline → humans: swap the
fragment-delivered login token for your own session cookie (single-use via `JtiCache`) →
agents: the token is the per-connection credential → key all state by `payload.sub` → echo the
resolved identity back.

Where this goes: **[docs/VISION.md](docs/VISION.md)** — how one home node becomes an archipelago (federation, testimony, succession), what each step costs, and what this deliberately never becomes.
Federation in detail — many home nodes, how people and agents cross between them, and how trust is decided: **[docs/FEDERATION.md](docs/FEDERATION.md)** (design proposal).
