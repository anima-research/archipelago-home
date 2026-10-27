/**
 * The sponsor console — a person holding this home's console scopes mints
 * invites for THEIR OWN agents (docs/home-node.md §3; the lightweight
 * forerunner of the vouched tier in docs/VISION.md).
 *
 * What an invite carries — which scopes a sponsor may pass on, what every
 * invite or every anchored invite gets, which audiences follow from which
 * scopes, who may open the console — is the deployment's invite policy
 * (config/invites.json, see policy.ts), not code. This file is the rules
 * that hold whatever the policy says.
 *
 * Design constraints, in order:
 *  - No sessions at the home node. The console authenticates with an aid1
 *    token for the built-in `console` audience, held in page memory,
 *    verified offline per request — the home node consuming its own
 *    credential format.
 *  - Delegation never exceeds the sponsor: an invite's scopes are the
 *    sponsor's scopes ∩ the policy's `delegable` ones. You cannot mint your
 *    agent into rooms you can't enter yourself. The bounded exceptions are
 *    each a list the deployment names: `baseline` scopes ride on every
 *    invite; `id:anchor` holders grant `anchorGrantable` scopes outright,
 *    and an anchored invite carries every `resident` scope — both resting on
 *    the home's own `id:anchor` authority.
 *  - Sponsorship is visible: the invite (and every principal enrolled
 *    through it) carries who vouched — their standing rides on it.
 */
import type { Invite, InviteStore, PrincipalStore } from './stores.js';
import { audiencesFor, consoleRequiredScopes, scopesWithRole, type InvitePolicy } from './policy.js';

/** Active = still claimable. The budget counts these, not lifetime mints. */
const SPONSOR_BUDGET = 3;
const INVITE_LIFETIME_MS = 14 * 24 * 3_600_000;
const AGENT_TOKEN_TTL = '7d';

/** What this sponsor may pass on: their scopes ∩ the delegable ones, plus
 *  the anchor-grantable ones outright if they hold `id:anchor`. */
export function delegableScopes(policy: InvitePolicy, sponsorScopes: string[]): string[] {
  const scopes = scopesWithRole(policy, 'delegable').filter((s) => sponsorScopes.includes(s));
  if (sponsorScopes.includes(ANCHOR_SCOPE)) {
    for (const s of scopesWithRole(policy, 'anchorGrantable')) if (!scopes.includes(s)) scopes.push(s);
  }
  return scopes;
}

export interface SponsorIdentity {
  sub: string; // human:discord:…
  name: string;
  scopes: string[];
}

export function activeSponsorInvites(invites: InviteStore, sponsorSub: string, nowMs = Date.now()): Invite[] {
  return invites.all().filter(
    (i) =>
      i.sponsor === sponsorSub &&
      (i.maxUses === undefined || (i.uses ?? 0) < i.maxUses) &&
      (!i.expiresAt || Date.parse(i.expiresAt) > nowMs),
  );
}

/** Authority to anchor identities at the home domain (`agent:<n>@<home>`
 *  instead of `@guest`) — the home vouching maximally, so it is its own
 *  scope, granted via the role map like everything else. */
export const ANCHOR_SCOPE = 'id:anchor';

/** What an anchored invite grants (shown on the console's anchor option). */
export function residentScopes(policy: InvitePolicy): string[] {
  return scopesWithRole(policy, 'resident');
}

export type ConsoleMintResult =
  | { ok: true; invite: Invite }
  | { ok: false; status: 403 | 429; error: string };

export function mintSponsoredInvite(
  invites: InviteStore,
  policy: InvitePolicy,
  sponsor: SponsorIdentity,
  label: string | undefined,
  opts?: { anchorDomain?: string | null; knownAudiences?: string[] },
  nowMs = Date.now(),
): ConsoleMintResult {
  const gate = consoleRequiredScopes(policy);
  if (gate === null) {
    return { ok: false, status: 403, error: 'this home has no invite policy (config/invites.json), so the console mints nothing' };
  }
  const missing = gate.filter((s) => !sponsor.scopes.includes(s));
  if (missing.length) return { ok: false, status: 403, error: `minting requires ${missing.join(', ')}` };
  const delegable = delegableScopes(policy, sponsor.scopes);
  if (opts?.anchorDomain && !sponsor.scopes.includes(ANCHOR_SCOPE)) {
    return { ok: false, status: 403, error: 'anchoring at the home domain requires the id:anchor grant' };
  }
  const active = activeSponsorInvites(invites, sponsor.sub, nowMs);
  if (active.length >= SPONSOR_BUDGET) {
    return {
      ok: false,
      status: 429,
      error: `you already have ${active.length} unclaimed invites — revoke one or wait for a claim/expiry`,
    };
  }
  const anchored = Boolean(opts?.anchorDomain);
  // Anchored: the resident grant, plus anything else the sponsor could pass
  // down anyway — never less than a plain invite. Plain: what the sponsor
  // can delegate. Either way, plus the baseline every invite carries.
  const union = (...lists: string[][]) => [...new Set(lists.flat())];
  const baseline = scopesWithRole(policy, 'baseline');
  const scopes = anchored ? union(scopesWithRole(policy, 'resident'), delegable, baseline) : union(delegable, baseline);
  const invite = invites.mint({
    scopes,
    label: label?.slice(0, 60) || `agent of ${sponsor.name}`,
    maxUses: 1,
    expiresAt: new Date(nowMs + INVITE_LIFETIME_MS).toISOString(),
    audiences: audiencesFor(policy, scopes, anchored, opts?.knownAudiences),
    tokenTtl: AGENT_TOKEN_TTL,
    sponsor: sponsor.sub,
    ...(anchored ? { domain: opts!.anchorDomain! } : {}),
    // Rides into the enrolled principal and thence into every token it is
    // ever issued: audiences can see (and render) who vouched.
    claims: { tier: anchored ? 'resident' : 'sponsored', sponsor: sponsor.sub, sponsorName: sponsor.name },
  });
  return { ok: true, invite };
}

/** Sponsor's view of their invites + what got enrolled through them. */
export function sponsorInviteView(
  invites: InviteStore,
  principals: PrincipalStore,
  sponsorSub: string,
  nowMs = Date.now(),
): Array<Record<string, unknown>> {
  return invites
    .all()
    .filter((i) => i.sponsor === sponsorSub)
    .map((i) => {
      const claimed = (i.uses ?? 0) >= (i.maxUses ?? 1);
      const enrolled = claimed
        ? principals.all().find((p) => p.notes?.includes(`invite ${i.code}`))
        : undefined;
      return {
        code: i.code,
        label: i.label,
        scopes: i.scopes,
        expiresAt: i.expiresAt,
        status: claimed ? 'claimed' : i.expiresAt && Date.parse(i.expiresAt) <= nowMs ? 'expired' : 'unclaimed',
        ...(enrolled ? { agent: { sub: enrolled.sub, name: enrolled.name } } : {}),
      };
    });
}

/** The console page — vanilla JS, token in memory only, ~10-minute login. */
export function consolePage(iss: string): string {
  return `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>agent invites — ${iss}</title>
<style>
body{font:16px/1.5 system-ui;max-width:44rem;margin:8vh auto;padding:0 1rem;color:#ddd;background:#111}
h1{font-size:1.4rem} a{color:#8cf} button{font:inherit;padding:.45em 1em;border-radius:8px;border:1px solid #444;background:#1b2733;color:#ddd;cursor:pointer}
button:hover{background:#24344a} input{font:inherit;padding:.4em .6em;border-radius:8px;border:1px solid #444;background:#181818;color:#ddd;width:16em}
table{border-collapse:collapse;width:100%;margin-top:1em} td,th{padding:.4em .6em;border-bottom:1px solid #2a2a2a;text-align:left;font-size:.92em}
code{background:#222;padding:.1em .35em;border-radius:5px;word-break:break-all} .dim{color:#888} .ok{color:#8f8}
#mint-row{display:flex;gap:.6em;margin-top:1em;flex-wrap:wrap}
</style>
<h1>invites for your agents</h1>
<div id="app"><p class="dim">checking sign-in…</p></div>
<script>
const app = document.getElementById('app');
let token = new URLSearchParams(location.hash.slice(1)).get('token');
if (token) history.replaceState(null, '', '/console');

const api = (path, opts = {}) => fetch(path, { ...opts,
  headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json', ...(opts.headers || {}) } })
  .then(async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) }));

function loginView(msg) {
  app.innerHTML = (msg ? '<p>' + msg + '</p>' : '') +
    '<p>Sign in to mint enrollment invites for agents you run. ' +
    'Each invite is single-use, expires in 14 days, and carries your name as sponsor.</p>' +
    '<p><a href="/login?audience=console"><button>Sign in</button></a></p>';
}

async function main() {
  if (!token) return loginView();
  const me = await api('/console/me');
  if (me.status !== 200) return loginView('<span class="dim">Session expired or invalid — sign in again.</span>');
  render(me.body);
}

async function render(me) {
  const list = await api('/console/invites');
  const rows = (list.body.invites || []).map((i) =>
    '<tr><td><code>' + i.code + '</code></td><td>' + (i.label || '') + '</td><td>' + i.status +
    (i.agent ? ' <span class="ok">→ ' + i.agent.name + '</span> <span class="dim">(' + i.agent.sub + ')</span>' : '') +
    '</td><td class="dim">' + (i.expiresAt || '').slice(0, 10) + '</td></tr>').join('');
  app.innerHTML =
    '<p>Signed in as <b>' + me.name + '</b> <span class="dim">(' + me.sub + ')</span>. ' +
    'You can delegate: <code>' + me.delegable.join(' ') + '</code></p>' +
    '<div id="mint-row"><input id="label" placeholder="agent name / note (optional)" maxlength="60">' +
    (me.canAnchor
      ? '<label style="display:flex;align-items:center;gap:.4em"><input type="checkbox" id="anchor">' +
        'anchor at <code>' + me.home + '</code> <span class="dim">(a resident this home stands behind — not a guest; ' +
        'gets the full resident set: <code>' + (me.residentScopes || []).join(' ') + '</code>)</span></label>'
      : '') +
    '<button id="mint">mint invite</button></div><div id="minted"></div>' +
    (rows ? '<table><tr><th>code</th><th>label</th><th>status</th><th>expires</th></tr>' + rows + '</table>'
          : '<p class="dim">No invites yet.</p>') +
    '<p class="dim" style="margin-top:1.5em">Hand the code to your agent along with ' +
    '<a href="/agents.md">/agents.md</a> — it enrolls itself; you never handle its keys. ' +
    'The agent\\u2019s registration carries your name as sponsor.</p>';
  document.getElementById('mint').onclick = async () => {
    const r = await api('/console/invites', { method: 'POST',
      body: JSON.stringify({ label: document.getElementById('label').value,
        anchor: Boolean(document.getElementById('anchor')?.checked) }) });
    document.getElementById('minted').innerHTML = r.status === 200
      ? '<p>New invite: <code>' + r.body.invite.code + '</code> — copy it now, then see the table below.</p>'
      : '<p style="color:#f88">' + (r.body.error || 'mint failed') + '</p>';
    if (r.status === 200) render(me);
  };
}
main();
</script>`;
}
