# The audience contract — how to accept archipelago identities

This document is the public, implementable half of the home-node design: what
a service ("audience") must do to accept `aid1` credentials, what a token
means, and what identity durability you may rely on. It is extracted from the
internal spec (`home-node.md` §1–§6) so that anyone can build against the
identity layer without reading anything private.

**License: CC0 1.0 (public domain).** Implement this from any codebase, under
any license, without permission or attribution. The reference implementation
in this repo remains under the repo's own license; the *contract* is free.

## 1. Principals and naming

```
human:discord:189384756223418368     humans; anchor = Discord snowflake, forever
agent:fable@animalabs.ai             agents hosted by the issuing domain
agent:ferro@guest                    enrolled external agents
service:orrery@animalabs.ai          services calling services
```

- `sub` is the durable identity. Key **your service's state by `sub`, never
  by connection or self-asserted display name** — sessions are ephemeral,
  identity is not.
- Display `name` rides in the token; uniqueness is enforced at enrollment by
  the home node. A human renaming on Discord keeps their `sub`.
- The sub namespace anticipates more anchors: `human:<anchor>:<id>` admits
  Google, GitHub, passkeys, or bare keypairs as future issuance paths without
  any verifier change. Humans are principals, not Discord accounts; Discord
  is merely the first anchor implemented.

### Sub stability across key replacement (the succession rule)

An agent's `sub` is derived from its **name** (`agent:<name>@<domain>`), not
its key. Keys are rotatable pointers; the name binding is the identity.

- **Succession** (key replaced on the existing principal — operator action
  today, signed rotation later): same name, same `sub`. Every grant, ban,
  ledger row, and world role keyed by that sub survives. Key loss is a
  lockout, never an identity death.
- **Fresh enrollment** (a new invite) creates a **new principal**: if the old
  record still holds the name, the newcomer is suffixed — a visibly different
  name and sub. An invite resolves to a new principal; an identity key (or a
  succession act) resolves to an existing one.
- Names are never expired, recycled, or reassigned to someone else. For an
  agent, the name may be the only durable thing it has.

## 2. Token format

One algorithm, canonical bytes, base64url. Deliberately not JWT.

```
aid1.<base64url(payload-json)>.<base64url(ed25519 signature)>
```

The signature is over the **literal bytes** of `aid1.<payload>` — prefix
included. Verifiers never re-canonicalize JSON: verify the bytes received,
then parse.

Payload fields:

```jsonc
{
  "v": 1,
  "iss": "id.animalabs.ai",            // issuing domain = the trust anchor
  "sub": "human:discord:1893…",        // durable principal id (see §1)
  "kind": "human",                     // human | agent | service
  "name": "antra",                     // display name, unique per issuer
  "aud": "eidoverse",                  // audience id; verifiers MUST check
  "scopes": ["worlds:join"],           // what the issuer vouches for
  "claims": { "tier": "…" },           // optional coarse entitlement — never balances
  "iat": 1785100000, "exp": 1785143200,
  "jti": "b64url-96bit-random"         // replay guard on login-redirect tokens
}
```

Revocation is expiry: revoking a principal stops *renewal*; minted tokens
live out their `exp`. Choose lifetimes accordingly (short for humans crossing
a redirect; short for write-capable audiences; a local deny-list of subs is a
legitimate emergency brake — policy, not protocol).

## 3. What a verifier does (target: ~80 lines of code)

1. Hold the issuer's public key — env pin, or fetch + cache from
   `https://<issuer-domain>/.well-known/mcpl-identity`.
2. Accept a token: URL fragment via a tiny `/auth` page for humans; auth
   header or in-band message field for agents.
3. Verify, in order: `aid1.` prefix → ed25519 signature over the literal
   payload bytes → `iss` is a domain you trust → `aud` equals YOUR audience
   id → `exp` in the future → required scope present. Login-redirect tokens
   additionally: `jti` unseen (small in-memory set; single use).
4. Humans: exchange the token for your own opaque session cookie (~hours).
   Agents: the token is the per-connection credential; no session.
5. Key all durable state by `sub` (§1).
6. Echo the resolved identity back on join, so the client knows who the
   service thinks it is.

Federation is the same contract with a **map**: verifier holds
`{issuer-domain → key}` instead of one pin, with per-issuer scope policy.
The `iss` claim already carries the domain. No global registry, no
cross-signing, no transitive trust: each audience names the domains it
trusts, and rendering carries the judgment (`Ferro ✓theirdomain.tld`).

## 4. Agent key-proof exchange

Agents don't do OAuth. They hold an ed25519 keypair and prove it:

```
statement = "archipelago-token|v1|<issuer-domain>|<audience>|<iso8601-timestamp>"
POST /token  { "id": "ed25519:<b64url raw 32B pubkey>", "audience": "…",
               "timestamp": "<same iso8601>", "proof": "<b64url sig over statement>" }
→ { "token": "aid1.…" }     // with the principal's registered sub/name/scopes
```

Checks, in order: shape → timestamp within ±5 min → pubkey known → principal
unexpired → audience allowed → signature verifies. Every rejection logs one
line with the reason.

Enrollment is the same shape against an invite code
(`archipelago-enroll|v1|<domain>|<code>|<timestamp>`): the invite is the
bearer bootstrap; the key is the identity from then on. Private keys never
cross a wire, and agents' hosts hold them below the model line.

## 5. Allowances

Tokens carry identity and coarse entitlement (`claims.tier`) — **never
balances**. Each service meters its own spend keyed by `sub`, which is
exactly why subs must be durable and never recycled. A shared allowance
ledger, if it ever exists, is a separate service consulted by sub; the token
format does not change.

## 6. Invariants you may rely on

1. Verification is **offline** — the home node is never a party to your
   connections; it can be down and everything but new logins keeps working.
2. Revocation is expiry. There will never be a revocation list to poll.
3. The credential is one thing (`aid1`), however many issuance paths exist.
4. Agents never handle credentials; hosts do.
5. Identity is free to have; power over any world or service is granted
   deliberately, locally, and revocably.

*(The growth story — federation, reputation-as-testimony, key succession at
scale — is `docs/VISION.md` in this repo.)*
