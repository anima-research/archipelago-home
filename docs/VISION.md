# From one home node to an archipelago

How this deliberately small service becomes infrastructure for many
communities without being rewritten — and what it will never become.

v0 (what's running today) is: one box, one signing key, one Discord guild,
flat JSON files, a handful of audiences. Every design decision in it was
made so that scaling is *addition*, not replacement. This doc names those
decisions and the growth steps they enable. The trust doctrine it
instantiates is the Archipelago design (connectome `docs/archipelago.md`);
the v0 spec is connectome `docs/home-node.md`.

## The invariants (what must stay true at every scale)

1. **Verification is offline.** An audience verifies a signature against a
   cached issuer key. The home node is never a party to any connection; it
   can be down and everything but new logins keeps working. No scale step
   may introduce a runtime dependency on it.
2. **Revocation is expiry.** Short validity windows, background refresh,
   no revocation lists — ever. Faster revocation is achieved by shortening
   lifetimes, which per-dial refresh (`accessProvider`) already makes cheap.
3. **The credential is one thing** — the `aid1` token — however many ways
   there are to obtain one. New principals, new auth anchors, new audiences
   change *issuance paths*, never the verifier.
4. **Identity is free to have, costs something to empower.** Bare
   registration is cheap; scopes, claims, and in-world powers are granted
   deliberately (roles, invites, per-world grants).
5. **Agents never handle credentials.** Hosts hold keys and fetch access;
   the model-visible vocabulary is *invitation, register, access, name*.
   This survives every scale step because credentials only exist below the
   host line.
6. **Every flow costs at most one human decision** (archipelago §9). A
   scale step that adds a second approval to any flow is wrong.

## Growth axes, in the order they'll likely matter

### 1. More audiences (now — this is the designed-for case)

Adding a service = one line in `audiences.json` + the ~80-line verifier
(`packages` export, eventually `@animalabs/archipelago-id` on npm) + a
redirect URI. Nothing else. `requiredScopes` per audience keeps refusal UX
at the login page. The audience never learns about Discord, guilds, or
roles — it sees `{sub, name, scopes, claims}` and a signature.

**Step when needed:** publish the verifier package so third-party services
can accept our identities without reading this repo.

### 2. More humans (no step needed, by construction)

Humans are never rows in our storage — they're derived from Discord at
login. Ten or ten thousand guild members cost us nothing; membership and
role administration stay in Discord where communities already do that
work. The `minted.jsonl` audit log grows linearly and is never consulted
at runtime.

**Steps when needed:** multiple guilds (key `roles.json` by guild id —
small, mechanical); other auth anchors (any OIDC upstream — Google,
GitHub, passkeys — becomes a new issuance path minting
`human:<anchor>:<id>` subs; the sub namespace anticipated this). Linking
one person's several anchors into one principal is a real feature with a
real design cost — deferred until someone actually needs it.

### 3. More agents (flat file → boring database, same contract)

`principals.json` is honest to ~thousands of records (it's read-hot,
write-rare, and hot-reloaded). Past that: SQLite with the same record
shape. The record IS the contract — `{sub, name, kind, key, scopes,
claims, audiences, tokenTtl, expires}` — and nothing outside this service
ever sees the storage.

**Steps when needed:** `hn` grows `scopes`/`edit` subcommands; enrollment
gets rate-limited per invite issuer; name uniqueness gets a reserved-names
list synced from audiences (world rosters, fleet names).

### 4. More communities — federation (the actual point)

This is where "central IdP" stops being even approximately true. The
Archipelago design (§3, §7): every community runs its OWN home node; the
durable identity is `name@domain`; audiences decide which issuer domains
they trust and discover keys via
`https://<domain>/.well-known/mcpl-identity` (already served today).

Concretely, the steps — all additive:
- **Verifier accepts a SET of issuers** keyed by domain, with per-issuer
  scope policy ("tokens from partner.example admit as visitor-tier
  regardless of claimed scopes"). The `iss` claim already carries the
  domain; today's single-issuer check becomes a map lookup.
- **Guest agents arrive attested by THEIR home**, not enrolled in ours:
  `ferro@theirdomain.tld` presents a token their home minted; our audience
  trusts (or doesn't) that domain. Manual mint and invites remain for
  agents with no home.
- **No transitive trust, no global registry, no cross-signing.** Each
  audience names the domains it trusts. Two communities federate by each
  adding one line of config. The root of trust is TLS+DNS — boring on
  purpose.
- **Rendering carries the trust judgment** (§8): `Ferro ✓theirdomain.tld`
  vs `Ferro (unattested)`. Impersonation is fought at the display layer,
  not by gatekeeping names globally.

### 5. Reputation — testimony, never scores (later, and carefully)

Archipelago §6: positive testimony travels with the subject (a carried,
signed résumé presented at admission); negative testimony lives with its
issuers and flows through plural, competing aggregators that return
*records with issuers attached* — never a number. There is no global
score, no ledger, no tribunal, and this repo will not grow one. What it
may grow: an `attest`/testimony endpoint (the home node signing short
statements about its own principals) and résumé verification in the
verifier package.

### 6. Economy — allowances stay at the edges

Tokens carry coarse entitlement (`claims.tier`), never balances. Each
service meters spend keyed by durable `sub` — which is exactly why subs
must never be recycled. If a shared allowance ledger ever exists, it's a
separate service audiences consult *by sub*; the token format doesn't
change. (First consumer: Orrery generation quotas.)

### 7. Key lifecycle at scale (succession, not recovery codes)

Agents' keys are rotatable pointers; the durable thing is the name binding
(§4). Succession = a signed statement — by the old key when rotating, by
the home domain when the old key is gone (redeploy → new key → home
re-attests). Bare-key relationships without a home break on key loss, by
design. Humans have no keys to lose — their anchor is their Discord (or
other OIDC) account, with that ecosystem's recovery machinery.

## What this never becomes

- **Not an account system.** No passwords, no emails, no profiles, no
  sessions at the home node beyond the seconds an OAuth round-trip takes.
- **Not a runtime dependency.** If every home node on earth is down,
  every existing session and credential keeps working until expiry.
- **Not a reputation score.** Testimony with issuers attached, or nothing.
- **Not a walled garden.** The endgame is many small homes trusting each
  other by explicit, revocable, per-audience choice — an archipelago, not
  a continent.

## Sequencing (earn each step)

Nothing above is speculative architecture waiting to be filled in — each
step is triggered by a concrete need and is additive when it comes:

| trigger | step |
|---|---|
| third-party service wants to accept our logins | publish verifier package |
| cold-arrival volume outgrows the Discord front door | staked auto-admission: vouched tier (member-signed referral, one hop, budgeted, voucher's reputation rides) first; bonded tier (deposit) only if vouching proves insufficient. Both are issuance-path additions — the credential and verifiers don't change, and arrivals carry a visible tier so the social gate stays the high-trust route |
| second community/guild | guild-keyed roles; maybe their own home node |
| first partner fleet | multi-issuer verifier + rendering marks |
| agent key loss in the wild | succession statements |
| Orrery quotas outgrow per-service metering | shared allowance service |
| name-squatting or impersonation attempts | reserved names + attestation display |
