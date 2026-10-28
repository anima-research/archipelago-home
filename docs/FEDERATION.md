# Federation: many home nodes, one way to cross

**Status:** design proposal, 2026-10-28. Nothing here is built yet. The decisions marked
*agreed* were settled with Antra; [open questions](#14-open-questions) are listed at the end.

**Why now:** a second home node (Lynx) is coming up with its own people, agents and
services. The design has to hold for dozens or hundreds of homes, not just two.

---

## 1. What this has to do

- **People and agents from one home use services of another**, both directions. A Lynx
  person can open Anima's docs; an Anima agent can join a Lynx service.
- **Scale to hundreds of homes** without pairwise setup. Two homes that have never heard of
  each other must still be able to meet, with whatever trust the receiving side grants
  strangers.
- **Some services need little trust to open up.** Docs will see visitors from many homes and
  only needs to know that *someone* answers for each of them.
- **Trust is pluggable and live.** Who believes what about which home is configuration and
  third-party evidence, re-evaluated as that evidence changes — not code, and not a fixed
  list of partners.

## 2. Decisions

| # | Decision | |
|---|---|---|
| 1 | The identifier says which home to sign in with: `alice@lynx.example`. No list of homes to choose from. | agreed |
| 2 | A visitor's `sub` is qualified by their home: `human:local:alice@lynx.example`. | agreed |
| 3 | A home reveals only what it chooses to each other home — by default, who the person is, not everything they can access. | agreed |
| 4 | The receiving home translates: it verifies the visitor's home and mints its own token for its own services. Services can also judge visitors themselves. | agreed |
| 5 | Evidence about homes comes from **oracles**: signed facts ("this home doesn't allow open signup") with the issuer attached, never a score. | agreed |
| 6 | Judgment is a **scheme**: a named, published policy. A service writes its own or delegates to a scheme published on a home node, including how rules combine. | agreed |
| 7 | Seed vocabularies for facts and events are proposed, and optional. | agreed |
| 8 | Anima runs an oracle. | agreed |
| 9 | Revocation is **pushed**. Grants don't expire by themselves; each scheme says what to do when the push channel goes quiet. | agreed |
| 10 | **Login handoff tokens keep a 10-minute expiry** and stay single-use. That expiry protects a token travelling in a URL, not trust. | agreed |
| 11 | Binding the same person's identities across homes is a separate, later step. | agreed |

## 3. Doctrine changes

Two of these reverse rules written elsewhere. When this is built, those documents change
with it, as they did for the home's own login.

1. **Revocation by push.** `connectome/docs/archipelago.md` §3 rule 2 says: *"Revocation =
   short validity windows. Hours-to-days, background refresh. Compromise is handled by not
   renewing. No CRLs, no revocation endpoints, ever."* This design replaces that with pushed,
   signed revocation events (§9). Short windows remain only for login handoff tokens.
2. **The home node as a runtime dependency becomes a per-scheme choice.** VISION.md says the
   home node is *"Not a runtime dependency. If every home node on earth is down, every
   existing session and credential keeps working until expiry."* Under push, what happens
   while a home is unreachable is set per grant by the scheme (§9.4): keep it, downgrade it,
   or refuse it.
3. **Who decides trust.** VISION §4 has each audience verify a set of issuers with its own
   per-issuer policy. Here the receiving home does the translating, so services stay
   single-issuer by default; a service may still judge visitors itself, or delegate its
   judgment to a published scheme. There is still no *implicit* transitive trust: a service
   trusts what its scheme names, and a scheme names its sources explicitly.
4. **What doesn't change:** one algorithm (ed25519 over literal bytes), the root of trust is
   TLS + DNS, no global registry, no reputation score. Oracles publish typed facts with
   their issuer attached, which is the "plural aggregators returning records with issuers
   attached" that VISION §5 already allows.

## 4. Names

**Handles.** Every principal has a handle `name@domain`. The domain names the home that
answers for it. People type their handle to sign in elsewhere; agents never type anything —
their credential already carries their home (§6.2).

**Subjects of visitors.** When home R admits a principal from home H, it qualifies the `sub`
H used:

| `sub` from H | becomes at R |
|---|---|
| `agent:ferro@lynx.example` (already names a domain H speaks for) | unchanged |
| `human:local:alice` | `human:local:alice@lynx.example` |
| `human:discord:123` | `human:discord:123@lynx.example` |
| `agent:ferro@guest` (a home-local qualifier, not a domain) | `agent:ferro@guest@lynx.example` |
| `agent:x@other.example` (a domain H does **not** speak for) | refused |

A home speaks for the domains its discovery document lists in `speaksFor` (§5). Anima
already needs two: of its 66 agents today, 17 are `agent:…@id.animalabs.ai` (anchored
through the console), 2 are `agent:…@animalabs.ai`, and 47 are `agent:…@guest`.

**Rendering.** Services show visitors with their home: `alice ✓lynx.example`. Display names
are unique only within a home; the domain suffix is what tells two Alices apart (archipelago
§8).

**Binding** `alice@lynx.example` to a local account at Anima comes later and works like
linking Discord to a local account today: the account keeps its own `sub`, the link adds a
way in.

## 5. Discovery

The file every home already serves grows the home's endpoints:

```jsonc
// GET https://id.animalabs.ai/.well-known/mcpl-identity
{
  "scheme": "ed25519",
  "domain": "id.animalabs.ai",
  "publicKey": "ed25519:yUGP67…",
  "speaksFor": ["animalabs.ai", "id.animalabs.ai"],
  "home": {
    "login":    "https://id.animalabs.ai/login",
    "callback": "https://id.animalabs.ai/federation/callback",
    "token":    "https://id.animalabs.ai/token",
    "events":   "wss://id.animalabs.ai/mcpl",
    "schemes":  "https://id.animalabs.ai/schemes/"
  },
  "attestations": [ "<signed oracle statements about this home — §8.3>" ]
}
```

A bare domain can delegate to its node, so handles stay short:

```jsonc
// GET https://animalabs.ai/.well-known/mcpl-identity
{ "delegate": "id.animalabs.ai" }
```

The resolver follows one delegation, then requires the node's `speaksFor` to include the
domain it came from.

**Fetching what strangers type.** A handle is user input, so discovery is a request to an
address a stranger chose. Guards: HTTPS only; public addresses only (no loopback, private
or link-local ranges, checked after DNS resolution); short timeouts; small response limit;
results cached; rate-limited per client.

## 6. Flows

### 6.1 A person from another home (identifier first)

Alice has an account at `lynx.example` and opens Anima's docs.

1. Docs sends her browser to `id.animalabs.ai/login?audience=docs`. The sign-in page has one
   field: *username or handle*. Local accounts (and passkey autofill) work as now; the
   Discord button stays on homes that use Discord.
2. She types `alice@lynx.example`. Anima resolves `lynx.example` (§5) and redirects to Lynx's
   `login` with `for=id.animalabs.ai`, a `state`, and `login_hint=alice`. The `state` is bound
   to her browser by an HttpOnly cookie — the same guard the Discord-link flow uses — so a
   flow started in one browser can't be finished in another.
3. Lynx signs her in its own way (her passkey there, password, Discord). The first time she
   goes to a home Lynx doesn't list, Lynx asks her once: *"id.animalabs.ai will know you as
   alice@lynx.example."* Lynx mints a **login handoff token** — 10 minutes, single use —
   addressed to `id.animalabs.ai`, carrying only what Lynx's release policy gives that home
   (§7), and returns it in the URL fragment to Anima's `callback`.
4. Anima verifies it against Lynx's key, checks it's addressed to Anima, uses it once, checks
   the browser binding, and evaluates its scheme for visitors (§8). It mints its own login
   handoff token for docs:
   ```jsonc
   { "iss": "id.animalabs.ai", "aud": "docs", "kind": "human",
     "sub": "human:local:alice@lynx.example", "name": "alice",
     "scopes": ["docs:use"],
     "claims": { "home": "lynx.example", "scheme": "id.animalabs.ai/schemes/standard",
                 "evidence": [ /* which facts, from whom (§8.4) */ ] } }
   ```
5. Docs receives an ordinary Anima token and starts its own session.

Passkeys fit this instead of fighting it: a passkey only works at the home that registered
it, and the handle sends her exactly there. Anima remembers the last handle in a cookie, so
the next visit is one click.

### 6.2 An agent from another home

Ferro, an agent of `lynx.example`, wants a token for Anima's docs.

1. Ferro's host holds an **attestation** from its home: a signed statement that key `K` is
   `agent:ferro@lynx.example`, with what Lynx releases about it. It is not a bearer
   credential — it names a key, and is useless without that key.
2. The host calls Anima's `token` endpoint with the existing key proof — the statement
   `archipelago-token|v1|id.animalabs.ai|docs|<timestamp>` signed with `K` — plus the
   attestation.
3. Anima resolves `lynx.example`, verifies the attestation and the proof, evaluates its
   scheme, and returns a token for docs.

The proof names Anima and a timestamp, so nobody can replay it elsewhere. Lynx mints nothing
per destination, and its agents keep working while Lynx is briefly down (within what the
scheme's staleness rules allow, §9.4).

### 6.3 Login handoff tokens

A login handoff token carries a sign-in across one redirect, inside a URL fragment. It keeps
a 10-minute expiry and a single-use `jti`. The expiry limits the damage of a URL leaking
through history, screenshots or extensions — something no revocation can catch, because
nobody knows it leaked. It also backs up the single-use check, which lives in memory and is
lost on restart.

Everything else that lasts — agent tokens, attestations, grants — stays valid until a pushed
event changes it (§9).

## 7. Release: what a home tells other homes

Each home decides what each other home learns about its people. The default is identity
only.

```jsonc
// config/release.json on the Lynx home
{
  "default": {
    "person":  ["joined"],
    "scopes":  [],
    "consent": "first-visit"
  },
  "homes": {
    "id.animalabs.ai": {
      "person":  ["joined", "admittedBy", "tier"],
      "scopes":  ["lynx:staff"],
      "consent": "never"
    }
  }
}
```

`sub`, `name` and `kind` are always released. `scopes` lists which of the person's scopes
may be shown to that home — never everything they can access. `person` lists which person
facts (§10.2) go with them. `consent` decides whether the person is asked before their home
vouches for them somewhere new.

## 8. Evidence: oracles and facts

### 8.1 Facts

A fact is a typed statement about a home or a person, with its issuer attached:

```
anima-oracle says:  lynx.example     signup: closed
anima-oracle says:  anyhome.social   signup: open, identityTracking: good
anima-oracle says:  spamfarm.lol     denied: true
lynx.example says:  alice            joined: 2026-03-14, admittedBy: operator
```

Values are typed — never a score. Two facts together can say what neither says alone: a
home that *tracks identities well but lets anyone sign up* makes its per-person facts worth
believing while making membership alone worth little; a home with closed signup makes
membership itself meaningful.

### 8.2 Sources

| Source | What it is |
|---|---|
| Oracle | A third party publishing signed facts about homes, and pushing changes (§9). Anyone can run one; Anima will (§11). |
| Local file | The operator's own word about homes they know. |
| Self | What a home says about itself in its discovery document. The weakest source; counts only where a rule names it. |
| Person facts | What a person's home releases about them (§7). Only as good as that home's `identityTracking`. |

A fact only counts where a rule names the source it came from. An oracle saying
"lynx.example is good" grants nothing unless the scheme relies on that oracle for that fact.

### 8.3 Statements travel with the subject

Positive facts can be carried. A home may include an oracle's signed statements about itself
in its discovery document (`attestations`), and the receiver verifies them offline without
calling the oracle. Negative facts — `denied`, a downgrade — never travel with the subject,
so a receiver learns those from the oracle itself, through the oracle's event stream.

### 8.4 Evidence in tokens

When a home admits a visitor, it records in the token which scheme it used and which facts,
from whom, the decision rested on (`claims.evidence`). A service can accept the home's
reading or re-check the same facts itself.

## 9. Liveness: pushed events

### 9.1 What is pushed

Signed events, numbered per publisher:

| Publisher | Events |
|---|---|
| A home | a principal revoked or disabled; a grant changed (e.g. a Discord role removed); a key rotated or compromised |
| An oracle | a fact about a home changed |
| A scheme publisher | a scheme updated |
| Everyone | heartbeat |

```jsonc
{ "v": 1, "issuer": "lynx.example", "seq": 1042, "at": "2026-10-28T09:14:03Z",
  "type": "revoked", "subject": "human:local:alice", "reason": "account disabled" }
```

Each event is signed by its issuer with the same construction as `aid1` tokens: ed25519
over the literal bytes, with its own prefix.

### 9.2 Channels

Events go out on the home's MCPL endpoint (published under `home.events`, and in
`/services` under `mcpl`) as a channel, and as server-sent events at
`GET /events?since=<seq>` for subscribers that don't speak MCPL. A subscriber resumes from
the last `seq` it saw and can tell when it missed something. A publisher keeps a retention
window of events, plus a snapshot of current state (who is revoked, current facts) for a
subscriber that fell behind further than that.

### 9.3 Relay

Because each event carries its issuer's signature, anyone can relay it without being able
to alter it. A home relays the events of the oracles its schemes rely on, so its own
services subscribe in one place. A receiving home subscribes to a visiting home's stream
when that home's first visitor arrives, and drops idle streams.

### 9.4 Staleness

A heartbeat separates "nothing happened" from "the channel is down". The freshness of a
decision is the time since the last heartbeat from each source it rests on. The scheme sets,
per grant, what happens when that gets too old:

```jsonc
"staleness": {
  "docs:read":  { "stale": "keep" },
  "docs:write": { "after": "1h", "stale": "downgrade", "to": ["docs:read"] },
  "gate:buy":   { "after": "5m", "stale": "refuse" }
}
```

A service that needs to react at once re-evaluates on each request; one that doesn't
re-evaluates at session start.

### 9.5 Tokens without built-in expiry

Today every `aid1` token has an `exp`, and the verifier refuses one without it. Under this
design only login handoff tokens keep one (§6.3). A token without `exp` is valid while its
signature verifies, no subscribed event has revoked it, and the scheme's staleness rules
allow it. Existing services keep receiving tokens with `exp` until they subscribe; an
audience opts in with a per-audience setting in `audiences.json`. Whether this stays `aid1`
with an optional `exp` or becomes a new version is open (§14).

## 10. Seed vocabularies (optional)

Oracles and schemes may define their own facts and event types. These seeds give the common
case shared names; a rule naming a fact a source doesn't publish simply doesn't match.

### 10.1 Facts about homes

| Fact | Values | Meaning |
|---|---|---|
| `signup` | `open` · `invite` · `closed` | how people and agents join |
| `identityTracking` | `good` · `unknown` · `poor` | subjects are stable and never recycled, accounts aren't shared, the home knows who is behind each principal |
| `denied` | `true` | the source does not vouch for this home at all |
| `contact` | URL or address | who answers for the home |

### 10.2 Facts about people (released by their home)

| Fact | Values |
|---|---|
| `joined` | date |
| `admittedBy` | `discord-role` · `invite` · `operator` · `open-signup` |
| `sponsor` | the `sub` who vouched for them |
| `tier` | the home's own tier name |

### 10.3 Event types

`revoked` · `grantChanged` · `keyRotated` · `keyCompromised` · `factChanged` ·
`schemeUpdated` · `heartbeat`

## 11. Schemes: published judgment

A scheme is a named, versioned, signed policy bundle. It lists which sources it believes for
which facts, how its rules combine, what it grants, how staleness is handled, and which
channels to subscribe to.

```jsonc
// https://id.animalabs.ai/schemes/standard  (version 3)
{
  "scheme":  "id.animalabs.ai/schemes/standard",
  "version": 3,
  "sources": {
    "anima": { "oracle": "https://oracle.animalabs.ai", "key": "ed25519:…" },
    "self":  { "discovery": true }
  },
  "combine": "union, refuse wins",
  "rules": [
    { "if": { "fact": "denied", "is": true, "from": ["anima"] }, "then": "refuse" },
    { "if": { "home": "lynx.example" }, "grant": ["docs:use", "worlds:spectate"],
      "translate": [{ "when": ["lynx:staff"], "grant": ["worlds:join"] }] },
    { "if": { "fact": "signup", "is": "closed", "from": ["anima"] }, "grant": ["docs:use"] },
    { "if": { "fact": "identityTracking", "is": "good", "from": ["anima"] },
      "grant": ["docs:read"],
      "and": { "if": { "person": "joined", "olderThan": "30d" }, "grant": ["docs:use"] } }
  ],
  "staleness": {
    "docs:read": { "stale": "keep" },
    "docs:use":  { "after": "1h", "stale": "downgrade", "to": ["docs:read"] }
  }
}
```

- **Combining rules is the scheme's choice** (`combine`). Seeds: `union, refuse wins`
  (all matching grants add up; any refusal wins) and `first match`.
- **`translate`** maps the scopes a home released into local ones, with the same rule shape
  as `invite-policy.json`.
- **Grants are scopes.** Each service's `requiredScopes` in `audiences.json` still decides
  who gets in, so opening docs to visitors is a line in the scheme and nothing in docs.

**Where a scheme is evaluated.** The receiving home evaluates its visitor scheme when
minting; that sets the ceiling — which services a visitor can get tokens for at all. A
service can evaluate a scheme itself, per session or per request, for finer and faster
decisions within that ceiling (read versus write, rate limits per home). Both use one
evaluator, shipped in the verifier package.

**Delegation.** A service writes its own scheme inline, or names a published one —
`{ "scheme": "id.animalabs.ai/schemes/standard" }` — and follows its updates live through
`schemeUpdated` events, optionally with local overrides on top.

**Code plug-in.** For logic rules can't express, a deployment's scheme can name a JS module in
its config folder that receives `(person, evidence)` and returns a grant. It runs inside the
identity service, so it is exactly as trusted as that service's config.

## 12. Anima's oracle

Anima runs an oracle at `oracle.animalabs.ai`, publishing signed facts about the homes it
knows and pushing changes.

- **Its own key**, separate from the issuer key: an oracle compromise must not let anyone
  mint identities, and the reverse.
- **A reviewed source of truth:** facts come from a file in a repo, so every change has an
  author and a diff, and the published history is the merge history.
- **First entries:** `id.animalabs.ai` itself and the Lynx home.
- **Relayed** by Anima's home node, so Anima's services subscribe in one place.

## 13. Security

- **"Any home that verifies" means anyone with a domain and a key.** Fine for low-trust
  services such as docs, with per-home rate limits and `claims.home` visible to the service.
  Anything that spends money or controls a body grants only to homes a scheme names.
- **A home speaks only for its own domains** (§4). A `sub` naming another domain is refused.
- **Replay.** Login handoff tokens are addressed to one receiver, single-use, short-lived,
  and bound to the browser that started the flow. Agent proofs name the receiving home and a
  timestamp.
- **Discovery is user-driven fetching** (§5): HTTPS, public addresses only, timeouts, size
  limits, caching, rate limits.
- **A compromised home key** can sign reassuring events about itself, so revoking that home
  can't come from the home. It comes from oracles (`denied`, `keyCompromised` as a fact
  about the home) and from key succession (VISION §7).
- **Oracle compromise** is limited by schemes naming oracles per fact; a scheme that relies
  on one oracle for a high-stakes grant inherits that oracle's risk, visibly.

## 14. Open questions

1. **Identity domain.** Handles at `animalabs.ai` (needs a delegation file on the main
   site) or at `id.animalabs.ai` (works today). This also decides what `iss` says.
2. **Consent defaults.** Ask on the first visit to every unlisted home, and never for homes
   in the release policy — or something stricter.
3. **Token format.** Optional `exp` within `aid1`, or a new version for tokens whose
   validity comes from pushed state.
4. **Revoking a compromised home key:** which sources a scheme should accept for that, and
   how succession statements interact with it.
5. **Event retention and snapshots:** how long a publisher keeps events, and the snapshot
   format.
6. **Scheme language:** whether the JSON rule shape above is enough before anyone needs the
   code plug-in.
7. **Oracle governance:** who reviews Anima's oracle file, and whether a home is told when a
   fact about it changes.
8. **Discord role changes as push events** need the home to watch the guild (bot gateway)
   rather than check at sign-in.
9. **Cross-home identity binding** (decision 11).

## 15. Build order

1. **This document**, for comment.
2. **The home's signed event stream** for its own principals, with heartbeats. This pays off
   before any federation: today `hn revoke` only stops new tokens, and existing ones keep
   working until they expire. With push, Anima's own services drop a revoked principal at
   once.
3. **Schemes and the shared evaluator**, at the home and in the verifier package.
4. **Identifier-first sign-in and visitor admission** at the home (§6.1), with the release
   policy (§7).
5. **Agent attestations and the token exchange** (§6.2).
6. **Anima's oracle**, with docs as the first service consuming it — it already accepts more
   than one issuer.
