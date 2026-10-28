# Federation: many home nodes, one way to cross

**Status:** Draft (revision 2, 2026-10-28). Draft→Accepted is gated on the
[conformance vectors](#16-conformance-vectors) existing as executable fixtures, as for the
mcpl RFCs. Nothing here is built yet. [Open questions](#14-open-questions) are listed near
the end.

**Why now:** a second home node (Lynx) is coming up with its own people, agents and
services. The design has to hold for dozens or hundreds of homes, not just two.

**Related:** this is the home-node half of the Connectome Desktop requirements §7.5,
*Network dynamics* (NET-1 to NET-8,
[Anima Docs, restricted](https://docs.animalabs.ai/d/duQI18Txo)). Sections below name the
NET item they implement so the two documents don't drift.

**Revision 2** (with two corrections from its review: agents' proof of relationship, and
freshness bounded by receiver challenges) takes in the first review on PR #7: revocation scope and reinstatement,
interest-scoped event streams with proof of relationship, a subscriber state contract,
conformance vectors, agent key lifecycle, key generations in place of token expiry, three
declared shapes for scheme code, `(iss, aud)` for services that judge visitors directly,
single-`@` subjects, showing the resolved home before redirecting, and collapsing the
verifier copies before anything builds on them.

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
| 2 | A visitor's `sub` is qualified by their home, with exactly one `@`: `human:local:alice@lynx.example`. | agreed |
| 3 | A home reveals only what it chooses to each other home — by default, who the person is. This covers event streams too (§9.1). | agreed |
| 4 | The receiving home translates: it verifies the visitor's home and mints its own token for its own services. A service may also judge visitors itself; it then verifies the `(iss, aud)` pair, since audience names are unique only within a home. | agreed; `(iss, aud)` from review |
| 5 | Evidence about homes comes from **oracles**: signed facts ("this home doesn't allow open signup") with the issuer attached, never a score. | agreed |
| 6 | Judgment is a **scheme**: a named, published policy. A service writes its own or delegates to a scheme published on a home node, including how rules combine. | agreed |
| 7 | Seed vocabularies for facts and events are proposed, and optional. | agreed |
| 8 | Anima runs an oracle. | agreed |
| 9 | Revocation is **pushed** over interest sessions (NET-1, NET-5). A revocation names its scope and holds until a signed reinstatement. Each scheme says what to do when a source goes quiet. | agreed; scope and reinstatement from review |
| 10 | **Login handoff tokens keep a 10-minute expiry** and stay single-use. That expiry protects a token travelling in a URL, not trust. | agreed |
| 11 | Binding the same person's identities across homes is a separate, later step. | agreed |
| 12 | Tokens stay `aid1`. `exp` becomes optional; the **issuer key generation** becomes mandatory and bounds how long anything must be remembered (§9.7). | from review |

## 3. Doctrine changes

Two of these reverse rules written elsewhere. When this is built, those documents change
with it, as they did for the home's own login.

1. **Revocation by push.** `connectome/docs/archipelago.md` §3 rule 2 says: *"Revocation =
   short validity windows. Hours-to-days, background refresh. Compromise is handled by not
   renewing. No CRLs, no revocation endpoints, ever."* This design replaces that with pushed,
   signed, scoped revocation events (§9). Short windows remain only for login handoff tokens.
2. **The home node as a runtime dependency becomes a per-scheme choice.** VISION.md says the
   home node is *"Not a runtime dependency. If every home node on earth is down, every
   existing session and credential keeps working until expiry."* Under push, what happens
   while a home is unreachable is set per grant by the scheme (§9.4): keep it, downgrade it,
   or refuse it. A sleeping home is simply down, and its people are stale meanwhile (NET-4).
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
H used. A subject always has exactly one `@`, so a verifier that splits on the first or the
last `@` gets the same answer:

| `sub` from H | becomes at R |
|---|---|
| `agent:ferro@lynx.example` (names a domain H speaks for) | unchanged |
| `human:local:alice` | `human:local:alice@lynx.example` |
| `human:discord:123` | `human:discord:123@lynx.example` |
| `agent:ferro@guest` (a home-local qualifier, not a domain) | `agent:ferro@lynx.example#guest` |
| `agent:x@other.example` (a domain H does **not** speak for) | refused |
| anything with more than one `@` | refused |

A home speaks for a domain only when **that domain's own discovery document resolves to the
home** (§5) — directly, or by delegation. A home's own `speaksFor` list proves nothing by
itself: a hostile home could list `lynx.example`, but `lynx.example`'s discovery document
won't point at it. Anima already needs two: of its 66 agents today, 17 are
`agent:…@id.animalabs.ai` (anchored through the console), 2 are `agent:…@animalabs.ai`, and
47 are `agent:…@guest`.

**Rendering.** Services show visitors with their home: `alice ✓lynx.example`. Display names
are unique only within a home; the domain suffix is what tells two Alices apart (archipelago
§8).

**Binding** `alice@lynx.example` to a local account at Anima comes later and works like
linking Discord to a local account today: the account keeps its own `sub`, the link adds a
way in.

## 5. Discovery

The file every home already serves grows the home's endpoints and its key generations:

```jsonc
// GET https://id.animalabs.ai/.well-known/mcpl-identity
{
  "scheme": "ed25519",
  "domain": "id.animalabs.ai",
  "publicKey": "ed25519:yUGP67…",            // the current generation, for today's verifiers
  "keys": [
    { "gen": 1, "publicKey": "ed25519:yUGP67…", "since": "2026-07-27" }
  ],
  "speaksFor": ["animalabs.ai", "id.animalabs.ai"],
  "home": {
    "login":    "https://id.animalabs.ai/login",
    "callback": "https://id.animalabs.ai/federation/callback",
    "token":    "https://id.animalabs.ai/token",
    "events":   "wss://id.animalabs.ai/mcpl",
    "feed":     "https://id.animalabs.ai/events",
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

**Confirmation runs in both directions.** The resolver follows at most one delegation, then
requires the node's `speaksFor` to include the domain it came from. Before accepting a `sub`
qualified by domain D from a home, the receiver resolves D itself and requires D's discovery
document — directly or through its one delegation — to name that home and its key.
`speaksFor` says which domains a home *claims*; each domain's own document is what confirms
it.

**Fetching what strangers type.** A handle is user input, so discovery is a request to an
address a stranger chose. Guards: HTTPS only; public addresses only (no loopback, private or
link-local ranges, checked after DNS resolution); short timeouts; small response limit;
results cached; rate-limited per client.

## 6. Flows

### 6.1 A person from another home (identifier first)

Alice has an account at `lynx.example` and opens Anima's docs.

1. Docs sends her browser to `id.animalabs.ai/login?audience=docs`. The sign-in page has one
   field: *username or handle*. Local accounts (and passkey autofill) work as now; the
   Discord button stays on homes that use Discord.
2. She types `alice@lynx.example`. Anima resolves `lynx.example` (§5) and **shows the
   resolved home before leaving**: *"You'll sign in at lynx.example"*, with a button to
   continue. Identifier-first is an open redirect by construction — a typed
   `alice@evil.example` would send her to evil's login page inside this flow — so the page
   names where she is going, and redirects only to the `login` endpoint of a home whose
   domain confirmed it. The redirect carries `for=id.animalabs.ai`, a `state`, and
   `login_hint=alice`. The `state` is bound to her browser by an HttpOnly cookie — the same
   guard the Discord-link flow uses — so a flow started in one browser can't be finished in
   another.
3. Lynx signs her in its own way (her passkey there, password, Discord). The first time she
   goes to a home Lynx doesn't list, Lynx asks her once: *"id.animalabs.ai will know you as
   alice@lynx.example."* Lynx mints a **login handoff token** — 10 minutes, single use —
   addressed to `id.animalabs.ai`, carrying only what Lynx's release policy gives that home
   (§7), and returns it in the URL fragment to Anima's `callback`.
4. Anima verifies it against Lynx's key, checks it's addressed to Anima, uses it once, and
   checks the browser binding. It then **registers interest in Alice with Lynx** (§9.1),
   presenting that same handoff token as proof of relationship. Lynx answers with Alice's
   current status, so Anima is synced for Alice at once: first contact costs one small
   exchange, not a full snapshot (NET-1, NET-7). Anima evaluates its scheme for visitors
   (§8, §11) and mints its own login handoff token for docs:
   ```jsonc
   { "iss": "id.animalabs.ai", "kg": 1, "aud": "docs", "kind": "human",
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

1. Ferro's host holds an **attestation** from its home: a signed statement that key `K`, of
   Ferro's key generation *n*, is `agent:ferro@lynx.example`, with what Lynx releases about
   it. It is not a bearer credential — it names a key, and is useless without that key.
2. The host calls Anima's `token` endpoint with the existing key proof — the statement
   `archipelago-token|v1|id.animalabs.ai|docs|<timestamp>` signed with `K` — plus the
   attestation.
3. Anima resolves `lynx.example`, verifies the attestation and the proof, registers interest
   in Ferro with Lynx — presenting both, since together they show Ferro came to Anima
   (§9.1) — evaluates its scheme, and returns a token for docs.

The proof names Anima and a timestamp, so nobody can replay it elsewhere. Lynx mints nothing
per destination, and its agents keep working while Lynx is briefly down, within what the
scheme's staleness rules allow (§9.4).

### 6.3 Agent key lifecycle

An agent's key is a pointer; the durable thing is the `sub` (VISION §7). The lifecycle is
explicit so that moving an agent never means "revoke everything and re-enrol":

- **Enrolment** (invite or operator, as today) attests key generation 1.
- **Rotation** attests a new key at generation *n*+1 and pushes `keyRotated` for that
  principal, naming the old and new generation. Proofs by the old key are refused once the
  event is applied. Revocation can target one key generation without touching the
  principal (§9.2).
- **Migration** to a new host is a rotation whose new key lives on the new host. There are
  never two live keys for one `sub`.
- **A fork** is a new principal, with its own `sub` and a `forkOf` fact naming the original,
  labelled as such wherever it is rendered — never a second live copy under the same `sub`.

### 6.4 Login handoff tokens

A login handoff token carries a sign-in across one redirect, inside a URL fragment. It keeps
a 10-minute expiry and a single-use `jti`. The expiry limits the damage of a URL leaking
through history, screenshots or extensions — something no revocation can catch, because
nobody knows it leaked. It also backs up the single-use check, which lives in memory and is
lost on restart.

Everything else that lasts — agent tokens, attestations, grants — stays valid until a pushed
event changes it, within the horizon of its key generation (§9.7).

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
vouches for them somewhere new. The same boundary holds for event streams: a home tells a
subscriber about a principal only when that subscriber has registered interest in them
(§9.1).

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
| Oracle | A third party publishing signed facts about homes, and pushing changes (§9). Anyone can run one; Anima will (§12). NET-4's certifiers are oracles that speak about principals. |
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

So a carried statement can be outdated without anyone saying so: the oracle may have
published `denied` since. Each carried statement names the oracle `seq` it was issued at. A
receiver synced with that oracle (§9.4) uses its own current state, which already includes
any later denial; a receiver not yet synced treats the carried statement as stale evidence,
and the scheme's staleness rules decide what it is worth. A carried statement never resets
the age of anything else (NET-4).

### 8.4 Evidence in tokens

When a home admits a visitor, it records in the token which scheme it used and which facts,
from whom, the decision rested on (`claims.evidence`). A service can accept the home's
reading or re-check the same facts itself.

## 9. Liveness: interest sessions and pushed events

### 9.1 Interest sessions (NET-1, NET-7)

Two kinds of stream:

- **Interest-scoped**, for anything about a principal. A receiver holds one session with each
  home it has visitors from, over which it **registers interest** in principals it admitted.
  Registering needs **proof of relationship** — evidence that this principal came to *this*
  receiver. The receiver authenticates as itself, and presents:
  - **for a person**, the login handoff token from §6.1, which the publisher addressed to the
    receiver;
  - **for an agent**, the attestation the publisher issued for the agent's key *and* the
    agent's key proof (§6.2) that names the receiver. The attestation alone names no
    receiver — it is reused everywhere — so the proof is what ties the visit to this
    receiver. The publisher checks that the proof is signed by the attested key, names the
    authenticated receiver, and carries a timestamp within its window.

  The publisher checks the credential against its own issuance record, answers with the
  principal's current status, then pushes changes for that principal on the session. A
  receiver never learns about principals it didn't admit, and the stream carries only what
  the release policy (§7) allows that receiver to know.
- **Public**, for facts about homes: an oracle's facts and a home's own key events concern
  homes, not people, and are broadcast to any subscriber.

An interest lapses when the receiver drops it, when the key generation it was registered
under retires (§9.7), or after an idle period the publisher sets, which the receiver renews
while it still serves the principal.

### 9.2 Events

Signed events, numbered without gaps per stream (per session for interest-scoped streams,
per publisher for public ones):

| Publisher | Events |
|---|---|
| A home | `revoked` and `reinstated` (each with a scope), `grantChanged` (e.g. a Discord role removed), `keyRotated` for a principal or for the home itself |
| An oracle | `factChanged` about a home |
| A scheme publisher | `schemeUpdated` |
| Everyone | `heartbeat`, carrying the stream's current `seq` |

```jsonc
{ "v": 1, "issuer": "lynx.example", "kg": 1, "seq": 1042, "at": "2026-10-28T09:14:03Z",
  "type": "revoked", "subject": "human:local:alice",
  "scope": "principal", "reason": "account disabled" }
```

**Revocation names what it revokes** (NET-2):

| `scope` | Revokes |
|---|---|
| `principal` | the principal entirely |
| `key:<gen>` | one of the principal's key generations; other keys and the `sub` stay |
| `tokensBefore:<iat>` | every token for the principal issued before that time |
| `grant:<scope>` | one scope, leaving the rest |

`revoked` is absorbing: a known revocation never degrades into staleness on disconnect, and
it ends only with a signed `reinstated` of the same scope, or a replacement through key
rotation or succession. Only the principal's own home can sign either; a revocation from
anyone else is ignored.

Each event is signed by its issuer with the same construction as `aid1` tokens: ed25519
over the literal bytes, with its own prefix, under the issuer key generation `kg`.

### 9.3 Channels and relays

Sessions run on the home's MCPL endpoint (published under `home.events`, and in `/services`
under `mcpl`). For a receiver that holds no session, the polled feed
`GET <home.feed>?since=<seq>` is the fallback (NET-5). A publisher keeps a retention window
of events, plus a signed snapshot of current state for a stream at a given `seq`.

**What a relay can do.** Because each event carries its issuer's signature, a relay can delay
or withhold events but never alter them. Withholding is detectable: heartbeats carry the
publisher's own `seq`, so a gap shows. Delay is bounded by challenges (§9.4): a relay can hold
back a gap-free run of events and heartbeats, but none of them answers a challenge the
receiver issues later, so the held-back run can't make anything fresh. A relay that holds back
or withholds everything makes the source go stale, which the scheme already handles. A home
relays the events of the oracles its schemes rely on, so its own services subscribe in one
place; challenges pass through the relay to the publisher and back.

### 9.4 Status: fresh, stale, revoked (NET-2, NET-3)

A receiver's view of a principal is one of:

- **fresh(age)** — the receiver is synced and has confirmed the principal recently;
- **stale(age)** — not confirmed recently, or not synced;
- **revoked(scope)** — a revocation applies.

**Challenges.** On each session the receiver regularly sends the publisher a fresh nonce
and notes the time on its own clock. The publisher answers with a signed heartbeat that
includes the nonce and its current `seq`. A heartbeat that doesn't carry the receiver's
outstanding nonce says the stream is alive but confirms nothing.

*Confirmed* means the receiver has applied the stream up to the `seq` stated in a signed
answer to one of its own challenges, and that `seq` covers the principal. **Synced** means it
has applied a verified snapshot (or the interest registration's answer) and every event after
it, with no gap, up to that `seq`. A live connection or a recent heartbeat is evidence of
liveness only, never of a complete view: a receiver holding `seq` 1042 whose challenge is
answered at 1050 is missing events, and the principal stays at its last-confirmed age until
it has caught up.

`age` is measured **on the receiver's clock, from when it issued the challenge** that the
confirming answer carried — never from the publisher's `at` (so clock skew between homes
can't manufacture freshness), and never from when the events arrived (so a relay or network
that delays a run of events can't either). Delay can only make a principal look older, never
younger.

**Unsynced is stale.** No fresh grant rests on a stream the receiver isn't synced with. The
scheme sets, per grant (per action, NET-3), what happens to a stale principal:

```jsonc
"staleness": {
  "docs:read":  { "stale": "keep" },
  "docs:write": { "after": "1h", "stale": "downgrade", "to": ["docs:read"] },
  "gate:buy":   { "after": "5m", "stale": "refuse" }
}
```

A service that needs to react at once re-evaluates on each request; one that doesn't
re-evaluates at session start.

### 9.5 Subscriber state

What a receiver keeps, so that every subscriber does the same thing instead of improvising:

| Per | Persisted |
|---|---|
| stream | last applied `seq`; the snapshot it started from (id and `seq`); synced or not; the outstanding challenge and when it was issued; the last answered challenge's time and `seq` |
| interest | the principal, the proof it was registered with, when it lapses |
| principal | current status (fresh, stale, revoked with scope) and when it was last confirmed, by the receiver's clock |
| home | key generations seen and which are retired |

**On restart**, every principal starts at its last-confirmed age (so it ages, it doesn't
reset), every stream is unsynced, and the receiver resumes each stream with `since=<seq>`.
**After falling out of the retention window**, it requests a snapshot for its interest set,
applies it, and replays from the snapshot's `seq`. **On a gap**, it resyncs from its cursor
with jittered backoff and a per-pair rate limit, so a gap seen by many receivers can't turn
into a resync storm (NET-7). Revocations are kept only while the key generation they apply
to is live (§9.7), which bounds this state.

### 9.6 What a revocation does to live state (NET-5)

Staleness covers grants. When a revocation lands at a service, the defaults in NET-5 apply:
stop new service — yes; close live sessions — by default, yes; queued data — per the policy
of each data layer; copies already disclosed — nothing can be done. The last two are still
open in the Desktop doc (Q20 (b)–(c)); step 3's first consumer needs an answer for itself.

### 9.7 Tokens, expiry and key generations

Today every `aid1` token has an `exp`, and the verifier refuses one without it. Under this
design:

- **`aid1` stays.** `exp` becomes optional; **`kg`, the issuer key generation, becomes
  mandatory.** A token is valid while its signature verifies under a live generation, no
  revocation in scope applies, and the scheme's staleness rules allow it.
- **Login handoff tokens keep `exp`** (§6.4).
- **Key generations bound memory.** A home rotates its signing key on a schedule, publishing
  generations in its discovery document (§5). Retiring a generation invalidates every token
  it signed, so a revocation need only be remembered while its generation is live, and a
  snapshot never lists more than that. Without this, a token minted in 2026 could be
  presented in 2031, and no publisher could ever drop a revocation.
- **Moving over.** Services that don't subscribe yet keep receiving tokens with `exp`. An
  audience opts in to the new behaviour with a setting in `audiences.json`.

The Desktop doc's NET-2 proposes the opposite default: `exp` as a hard outer bound, with a
7-day `exp` and 60-second freshness given as sound. Here the outer bound is the key
generation instead. The two need reconciling (§14).

## 10. Seed vocabularies (optional)

Oracles and schemes may define their own facts and event types. These seeds give the common
case shared names; a rule naming a fact a source doesn't publish simply doesn't match.

### 10.1 Facts about homes

| Fact | Values | Meaning |
|---|---|---|
| `signup` | `open` · `invite` · `closed` | how people and agents join |
| `identityTracking` | `good` · `unknown` · `poor` | subjects are stable and never recycled, accounts aren't shared, the home knows who is behind each principal |
| `denied` | `true` | the source does not vouch for this home at all |
| `keyCompromised` | key generation | the source believes this home key generation is compromised |
| `contact` | URL or address | who answers for the home |

### 10.2 Facts about people (released by their home)

| Fact | Values |
|---|---|
| `joined` | date |
| `admittedBy` | `discord-role` · `invite` · `operator` · `open-signup` |
| `sponsor` | the `sub` who vouched for them |
| `tier` | the home's own tier name |
| `forkOf` | the `sub` this principal was forked from (§6.3) |

### 10.3 Event types

`revoked` · `reinstated` · `grantChanged` · `keyRotated` · `factChanged` · `schemeUpdated` ·
`heartbeat`

## 11. Schemes: published judgment

A scheme is a named, versioned, signed policy bundle. It lists which sources it believes for
which facts, how its rules combine, what it grants, how staleness is handled, and which
streams to subscribe to.

```jsonc
// https://id.animalabs.ai/schemes/standard  (version 3)
{
  "scheme":     "id.animalabs.ai/schemes/standard",
  "version":    3,
  "evaluation": "rules",
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
evaluator, shipped in the verifier package. A service that judges a foreign token directly
verifies `(iss, aud)` together: Lynx may have a `docs` too.

**Delegation.** A service writes its own scheme inline, or names a published one —
`{ "scheme": "id.animalabs.ai/schemes/standard" }` — and follows its updates live through
`schemeUpdated` events, optionally with local overrides on top.

**How a scheme computes** is declared in `evaluation`, one of three shapes:

1. **`rules`** — the JSON rules above, extended as needs arise.
2. **`module`** — a sandboxed pure function (WASM or an isolate): input `(person, evidence)`,
   output a grant, no I/O, bounded time and memory, identified by content hash.
3. **`remote`** — the scheme runs at its publisher or a delegate, and the service accepts a
   **signed decision**. That makes the publisher a runtime dependency of the scheme and lets
   it see the evidence, which the scheme states.

A receiver refuses an unsandboxed module from any remote publisher. A deployment may still
run an unsandboxed module from its own config folder, which is exactly as trusted as that
deployment's config.

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

Abuse surfaces and their bounds follow the Desktop doc's NET-7; the federation-specific ones:

- **"Any home that verifies" means anyone with a domain and a key.** Fine for low-trust
  services such as docs, with per-home rate limits and `claims.home` visible to the service.
  Anything that spends money or controls a body grants only to homes a scheme names.
- **A home speaks only for its own domains** (§4), confirmed from each domain's side: the
  receiver resolves the domain in a `sub` and requires it to point at the signing home. A
  home listing someone else's domain in `speaksFor` gains nothing.
- **Open redirect.** Identifier-first sends the browser wherever a typed domain says. The
  sign-in page names the resolved home before leaving, and redirects only to the `login`
  endpoint of a confirmed home (§6.1).
- **Replay.** Login handoff tokens are addressed to one receiver, single-use, short-lived,
  and bound to the browser that started the flow. Agent proofs name the receiving home and a
  timestamp.
- **Subscription flooding.** Interest needs proof of relationship (§9.1); nobody can watch
  a principal they never admitted.
- **False revocation.** Only a principal's own home can sign a revocation or a reinstatement
  for it.
- **Audience collisions.** Services judging foreign tokens directly verify `(iss, aud)`.
- **Discovery is user-driven fetching** (§5): HTTPS, public addresses only, timeouts, size
  limits, caching, rate limits.
- **A compromised home key** can sign reassuring events about itself, so revoking that home
  can't come from the home. It comes from oracles (`denied`, `keyCompromised`) and from key
  succession (VISION §7).
- **Oracle compromise** is limited by schemes naming oracles per fact; a scheme that relies
  on one oracle for a high-stakes grant inherits that oracle's risk, visibly.
- **Scheme code from elsewhere** never runs unsandboxed (§11).

## 14. Open questions

1. **Identity domain.** Handles at `animalabs.ai` (needs a delegation file on the main
   site) or at `id.animalabs.ai` (works today). This also decides what `iss` says.
2. **Consent defaults.** Ask on the first visit to every unlisted home, and never for homes
   in the release policy — or something stricter.
3. **`exp` against key generations.** This revision makes the key generation the outer
   bound; the Desktop doc's NET-2 proposes `exp`. Which bound, or both, and the rotation
   schedule for issuer keys.
4. **Revoking a compromised home key:** which sources a scheme should accept for that, and
   how succession statements interact with it.
5. **Retention.** Key generations bound what must be remembered; still open is how long a
   publisher keeps replayable events before a subscriber must take a snapshot, and the
   snapshot format.
6. **Interest lapse.** The idle period after which a publisher drops an interest, and how a
   receiver renews it.
7. **Sandbox runtime** for `module` schemes: WASM, a JS isolate, or both.
8. **Oracle governance:** who reviews Anima's oracle file, and whether a home is told when a
   fact about it changes.
9. **Discord role changes as push events** need the home to watch the guild (bot gateway)
   rather than check at sign-in.
10. **Live state on revocation:** queued data and disclosed copies (Desktop Q20 (b)–(c)).
11. **Cross-home identity binding** (decision 11).

## 15. Build order

1. **This document**, to Accepted once the conformance vectors (§16) exist as executable
   fixtures.
2. **Collapse the verifier copies.** Several services carry their own copy of the `aid1`
   verifier — eidoverse-worlds, gate, archipelago-docs, ecowitt, clawblox in TypeScript,
   orrery in Python. Make `@animalabs/archipelago-home/verifier` the only TypeScript copy and
   add a Python twin, so the revocation hook and the evaluator each land once rather than
   forking across every service.
3. **The home's event stream:** interest sessions with proof of relationship, scoped
   revocation and reinstatement, heartbeats carrying `seq`, snapshots per interest set, the
   polled fallback, and the subscriber side in the verifier package. This pays off before any
   federation: today `hn revoke` only stops new tokens, and existing ones keep working until
   they expire. With push, Anima's own services drop a revoked principal at once.
4. **Schemes and the shared evaluator**, `rules` first.
5. **Identifier-first sign-in and visitor admission** at the home (§6.1), with the release
   policy (§7).
6. **Agent attestations with key generations, and the token exchange** (§6.2, §6.3).
7. **Anima's oracle**, with docs as the first service consuming it — it already accepts more
   than one issuer.

## 16. Conformance vectors

**Acceptance criterion:** before this document moves Draft→Accepted, these vectors freeze
as executable fixtures (`conformance/federation-vectors.json`) and run against the home node
and at least one subscribing service.

| # | Vector | Expected |
|---|---|---|
| 1 | A home signs `agent:ferro@lynx.example`; `lynx.example`'s discovery resolves to that home | accepted, `sub` unchanged |
| 2 | A home lists `lynx.example` in `speaksFor`; `lynx.example`'s discovery names a different home | refused |
| 3 | A discovery document delegates twice | refused |
| 4 | `agent:ferro@guest` from `lynx.example` | becomes `agent:ferro@lynx.example#guest` |
| 5 | A `sub` with two `@` | refused |
| 6 | New receiver: heartbeat at `seq` 1050, nothing applied | principal stale; grants follow the staleness rules |
| 7 | Applied up to 1042, then a heartbeat at 1050 | stays at its last-confirmed age until 1043–1050 are applied, then fresh |
| 8 | Carried statement issued at oracle `seq` 1000; oracle published `denied` at 1010 | a synced receiver refuses; an unsynced one treats the statement as stale |
| 9 | First visitor from a new home | the interest registration's answer makes the principal fresh, with no full snapshot |
| 10 | Interest registration without proof of relationship | refused |
| 10a | Interest registration for an agent with its attestation but no key proof naming the receiver | refused; with the attestation and a proof naming the receiver, accepted |
| 11 | `revoked` with `key:2`, then a proof by key generation 3 | accepted; a proof by generation 2 is refused |
| 12 | `revoked` with `tokensBefore:<t>` | tokens with `iat` before `t` refused, later ones accepted |
| 13 | `revoked` with `grant:docs:write` | `docs:write` removed, other grants kept |
| 14 | `revoked`, connection lost, old token presented | still refused: revocation doesn't decay into staleness |
| 15 | `revoked` then `reinstated` with the same scope | accepted again |
| 16 | A revocation signed by a home other than the principal's | ignored |
| 17 | Token signed under a retired issuer key generation | refused; the snapshot omits revocations for that generation |
| 18 | Event `at` far in the future | age measured from the receiver's challenge; no freshness gained |
| 18a | A relay holds a gap-free run of events and heartbeats, releases it after the oracle publishes `denied` | none of the held heartbeats answers the receiver's current challenge; the principal is not made fresh |
| 19 | A service judging directly gets a token with `aud: docs` from another issuer | refused unless `(iss, aud)` matches |
| 20 | A scheme from a remote publisher carrying an unsandboxed module | refused |
