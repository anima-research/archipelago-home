# archipelago-home

Connectome home node v0 — identity issuance for humans (Discord OAuth + guild-role→scope, or the
home's own login: username + password + TOTP, passkeys, and Google) and agents (ed25519 key-proof or
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
when a Discord-linked person signs in another way), `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET`
(optional; Google login), `EMAIL_PROVIDER` + `RESEND_API_KEY` + `EMAIL_FROM` and
`STRIPE_WEBHOOK_SECRET` (optional; ticket holders' email sign-in, below). First run generates `data/issuer-key.pem`
(0600) — **the** issuer key; guard it, never commit it. `data/accounts.json` (0600) holds
password hashes, TOTP secrets and passkey keys — back it up with the issuer key, and guard it
the same way.

Discord app setup: dev portal → OAuth2 → redirect URI `https://<HN_DOMAIN>/oauth/callback`.
Scopes requested at login: `identify guilds.members.read` (no bot).

Google setup: Cloud console → Google Auth Platform → Branding (app name, support email), Audience
External → Publish; Data Access: `openid`, `…/auth/userinfo.email`, `…/auth/userinfo.profile`
(all non-sensitive, so no verification review); Clients → Web application, redirect URI
`https://<HN_DOMAIN>/oauth/google/callback`, no JavaScript origins. Code flow with PKCE.

Google carries no roles, so it **grants nothing by itself**: it opens an account that already
exists — one that linked Google at `/account`, or one the operator invited by address
(`hn user add alice --google alice@gmail.com --scopes …`), which the first sign-in claims if Google
is **authoritative** for that address: Gmail, or a Google Workspace account. For any other address
`email_verified` only means the address was checked once (the mailbox may have changed hands), so
such an invite can't be claimed through Google — send a setup link instead and they link Google
after. From then on the link is by Google's account id, not the address. A Google account the node
doesn't know gets an empty row only while an audience is open to newcomers (below).

An account made by a Google sign-in (`human:google:<sub>`) can't unlink Google — it *is* that
identity, as `human:discord:` rows are for Discord. Nor can an account the operator restricted
(`hn user restrict`) unlink a sign-in method: it would come back unrestricted on its own.

## Human sign-in

`/login?audience=…` is a chooser: **Continue with Discord**, **Continue with Google**,
**username + password** (then a TOTP code if they turned one on), **passkey** (also offered
as autofill in the username field), or **Email** (a one-time code, for ticket holders — below).
Every path ends the same way — a 10-minute aid1 token in the audience's URL fragment —
so audiences change nothing. `?via=discord` / `?via=google` skips the chooser.

People manage their own sign-in at **`/account`**: set a username + password (a Discord person
keeps their `human:discord:` sub), turn TOTP on (QR + ten single-use recovery codes), add or
remove passkeys, link Discord to a local account, link or unlink Google. The page's credential is its own login token,
so it is always a recent sign-in.

Accounts for people without Discord come from the operator — there is no open sign-up. Run
`hn user` as the service user (`sudo -u hn …` on the identity box; it refuses to run as root,
since a root-owned 0600 `accounts.json` would lock the service out):

```sh
hn user add alice --scopes worlds:join,worlds:spectate   # → one-time setup link (72h)
hn user add bea --google bea@gmail.com --scopes …         # → no link: Continue with Google claims it
hn user ls                                                # who has what (no secrets)
hn user reset alice [--clear-2fa] [--clear-passkeys]      # → new setup link
hn user set alice --scopes worlds:join,orrery:use         # operator grant (Discord roles add on top)
hn user set alice --google alice@work.example             # (re)invite by Google address; --google none drops it
hn user disable alice    hn user enable alice
```

Throttles: 5 wrong passwords lock that username for 15 minutes; 10 wrong codes lock its second
factor for 15 minutes; a sign-in ticket allows 5 code tries. Passkeys are never throttled by
these, so they remain a way in during a lockout.

## Audiences open to newcomers

An audience with `"signup": {}` in `audiences.json` (optionally `{"scopes": [...]}`, default its
`requiredScopes`) admits anyone who signs in — a Google account the node has never seen, or a
Discord account with no role — holding those scopes **for that audience only**. Everywhere else
they hold nothing. Per-person `withhold` still applies.

While any audience is open, a Google newcomer gets an account row (`human:google:<sub>`) on first
sign-in **wherever they started** — sign-in settings, or a service they can't use yet. The row
holds no scopes, so a closed audience still refuses them; its refusal page (and the account page)
lists the sites open to everyone, so someone who came in the wrong door sees where to go.

Inviting someone who already signed up this way (`hn user add <name> --google <their address>`)
doesn't make a second account: their existing `human:google:<sub>` row takes the username and the
`--scopes`, and keeps its sub — so what services already hold under it (docs shares, comments) stays
theirs. Only when Google is authoritative for that address on the row (`google.verified`, refreshed
at each sign-in) — the same proof a fresh invite asks of its first sign-in.

## Access codes

A code grants named **audiences** (and the scopes they need) to whoever redeems it: on the sign-in
page ("Have an access code?", which also signs a newcomer up through Google or Discord), or later
under sign-in settings. What a code grants counts **only for its own audiences**: it never widens
what the person holds elsewhere (audiences without `requiredScopes` take any grant, and a code for
one service must not open those).

```sh
hn code add --aud speakers.coev.ai --scopes speakers:member --label "Speaker ranker" --max-uses 25 [--expires 14d]
                                       # → the code, shown once (stored hashed in data/codes.json, 0600)
hn code ls                             # uses, and who redeemed what
hn code close <id>                     # no new redemptions; what it gave stays
hn code revoke <id>                    # and take back what it gave, at each holder's next sign-in
```

A code can ride a link: `https://<HN_DOMAIN>/login?audience=<aud>#code=<code>` (fragment, so it
stays out of logs). `--expires` and `--max-uses` limit redeeming, not access once redeemed.

## Ticket holders: email sign-in

Someone who holds a **ticket** — an email address on the ticket list — makes an account and signs
in with just that address: the sign-in page's **Email** method sends a 6-digit code (good for 10
minutes, 5 tries), and the first code that comes back makes their row (`human:email:<random id>`,
never the address) with the address as a verified sign-in method and the ticket's grant on it.
No password; they can add a passkey, password or two-factor code afterwards under sign-in settings.
Later sign-ins with the same mailbox (case, and for Gmail dots and `+tags`, don't matter) open the
same account; one ticket is one account. Someone who already has an account links the address there
instead (**Email → Send a code** on `/account`) and the ticket is taken up by that account.

Tickets arrive two ways:

- **Stripe**: register `https://<HN_DOMAIN>/stripe/webhook` in the Stripe dashboard for the
  `checkout.session.completed` event (also honoured: `payment_intent.succeeded` when it carries a
  `receipt_email`), and set its signing secret as `STRIPE_WEBHOOK_SECRET`. A paid checkout's address
  gets a ticket (source `stripe:<event id>`; redeliveries are recognised by event id). Nothing else
  about the payment is kept. Unset = the route is 404.
- **`hn ticket add <email>`** by hand.

What a ticket grants comes from `config/ticket-defaults.json` (copy `config/ticket-defaults.example.json`; hot-reloaded,
a typo'd file is refused and the last good one stays) unless `hn ticket add` says otherwise. The grant
is **copied onto the account** when the ticket is taken up and counts **for the ticket's audiences only**,
like an access code's — so `hn ticket rm` only stops future sign-ups with that address; an account
already made keeps what it was given (`hn user disable <sub>` shuts it).

```sh
hn ticket add pat@example.org [--note "…"] [--scopes a,b] [--audiences x,y]   # defaults: config/ticket-defaults.json
hn ticket ls                                                                   # holders, and which account took each up
hn ticket rm pat@example.org
```

A "you're in" page can link straight to the sign-in with the address filled in:
`https://<HN_DOMAIN>/login?audience=<aud>&email=<address>` (nothing is sent until they ask).

The request for a code answers the same way whether or not the address holds a ticket, and is limited to
3 codes per address and 10 per client address in 10 minutes. The answer never says who holds one.

Sending mail: `EMAIL_PROVIDER=resend` with `RESEND_API_KEY` and `EMAIL_FROM` (e.g.
`"Home <no-reply@id.example>"` — the sending domain needs the provider's DKIM and SPF DNS records, or
nothing is delivered), or `EMAIL_PROVIDER=log`, which prints the code to the server log (development
only; refused on an `https://` public URL). Unset = the Email method isn't offered and its routes are
404. `data/tickets.json` (0600) is the ticket list — back it up with the rest of `data/`.

## The deployment's policy (config/)

What the node knows about *your* services is configuration, hot-reloaded (edit, save, no
restart; a file that doesn't parse or validate is refused and the last good one stays):

| file | says |
|---|---|
| `audiences.json` | the services: login redirect, scopes a login must hold, API and MCPL endpoints (`/services`) |
| `roles.json` | Discord guild roles → scopes (only with Discord on) |
| `invite-policy.json` | the sponsor console: who may open it, which scopes a sponsor may pass to their agent, what every invite and every anchored invite carries, which audiences follow from which scopes |
| `ticket-defaults.json` | what a ticket grants by default (audiences + scopes), for the Stripe webhook and `hn ticket add` without flags |

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
Federation in detail — many home nodes, how people and agents cross between them, and how trust is decided: **[docs/FEDERATION.md](docs/FEDERATION.md)** (design proposal).
