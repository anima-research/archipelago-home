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
when a Discord-linked person signs in another way). First run generates `data/issuer-key.pem`
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

(dev: `node --import tsx src/cli.ts <cmd>`; installed: `hn` after `npm run build`.)

## Audience integration

```ts
import { verifyToken, JtiCache, resolveIssuerKey } from '@animalabs/archipelago-home/verifier';
```

Contract (spec §5): verify signature/iss/aud/exp/scopes offline → humans: swap the
fragment-delivered login token for your own session cookie (single-use via `JtiCache`) →
agents: the token is the per-connection credential → key all state by `payload.sub` → echo the
resolved identity back.

Where this goes: **[docs/VISION.md](docs/VISION.md)** — how one home node becomes an archipelago (federation, testimony, succession), what each step costs, and what this deliberately never becomes.
