/**
 * The home node HTTP service (docs/home-node.md §3). Plain node:http, no
 * framework. TLS is the fronting proxy's job (caddy/tailscale-serve);
 * default bind is loopback. The human sign-in routes live in human.ts.
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadOrCreateIssuerKey, type IssuerKey } from './keys.js';
import { verifyToken, type Aid1Payload } from './token.js';
import { handleEnroll, handleTokenRequest, type ExchangeDeps } from './exchange.js';
import {
  ANCHOR_SCOPE, delegableScopes, mintSponsoredInvite, residentScopes, sponsorInviteView,
} from './console.js';
import { consoleRequiredScopes, invitePolicyStore, type InvitePolicy } from './policy.js';
import { AccountStore } from './accounts.js';
import { HumanAuth } from './human.js';
import { CodeStore } from './codes.js';
import {
  clean, maskEmail, noDefaultsMessage, takeBackTicket, ticketDefaultsStore, ticketGrantProblem, ticketPlaceholderSub, ticketSponsorSubs,
  TicketStore, usableEmail, type RemovedTicket, type Ticket, type TicketDefaults,
} from './tickets.js';
import { displayName, nameProblem, TICKET_HOLDER_NAME } from './accounts.js';
import type { SponsorIdentity } from './console.js';
import { emailKey } from './google.js';
import { emailSenderFromConfig, type EmailSender } from './email.js';
import type { FetchLike } from './oauth.js';
import { consoleMovedPage, enrollPage, homePage, siteStore, type SiteInfo } from './site.js';
import { SessionStore } from './sessions.js';
import { esc, html, json, page, readJson } from './http.js';
import {
  audiencesStore,
  InviteStore,
  MintLog,
  PrincipalStore,
  rolesStore,
  mcplDirectory,
  serviceDirectory,
  type AudiencesConfig,
  type RolesConfig,
} from './stores.js';
import type { JsonStore } from './stores.js';

export interface ServerConfig {
  iss: string; // e.g. id.animalabs.ai
  publicUrl: string; // e.g. https://id.animalabs.ai
  bind: string;
  port: number;
  dataDir: string;
  configDir: string;
  discordClientId?: string;
  discordClientSecret?: string;
  /** Bot token for server-side role lookup (shrinks OAuth to `identify`). */
  discordBotToken?: string;
  googleClientId?: string;
  googleClientSecret?: string;
  /** A header the fronting proxy overwrites with the client address (e.g.
   *  `x-real-ip` on Railway), trusted from any peer — only for deployments
   *  where every request arrives through that proxy. Unset: X-Real-IP is
   *  trusted from loopback only. */
  clientIpHeader?: string;
  /** `resend` | `log` (email.ts); unset = no email sign-in. */
  emailProvider?: string;
  resendApiKey?: string;
  emailFrom?: string;
  /** Bearer token the ticket site presents at /tickets; unset = the API is off (404). */
  ticketsToken?: string;
}

export function configFromEnv(env = process.env): ServerConfig {
  const iss = env.HN_DOMAIN ?? 'id.animalabs.ai';
  return {
    iss,
    publicUrl: env.HN_PUBLIC_URL ?? `https://${iss}`,
    bind: env.HN_BIND ?? '127.0.0.1',
    port: Number(env.HN_PORT ?? 7360),
    dataDir: env.HN_DATA_DIR ?? 'data',
    configDir: env.HN_CONFIG_DIR ?? 'config',
    discordClientId: env.DISCORD_CLIENT_ID,
    discordClientSecret: env.DISCORD_CLIENT_SECRET,
    discordBotToken: env.HN_BOT_TOKEN,
    googleClientId: env.GOOGLE_CLIENT_ID,
    googleClientSecret: env.GOOGLE_CLIENT_SECRET,
    emailProvider: env.EMAIL_PROVIDER,
    resendApiKey: env.RESEND_API_KEY,
    emailFrom: env.EMAIL_FROM,
    ticketsToken: env.HN_TICKETS_TOKEN || undefined,
  };
}

/**
 * The client address for rate limiting. Behind the local reverse proxy every
 * request arrives from loopback, which would put the whole internet in one
 * bucket; the proxy overwrites X-Real-IP with the real client, so it is trusted
 * only when the connection itself comes from loopback. On a platform whose
 * edge proxy is not on loopback (Railway), `trustedHeader` names the header
 * that proxy overwrites, and it is trusted from any peer.
 */
export function clientIp(req: Pick<IncomingMessage, 'headers' | 'socket'>, trustedHeader?: string): string {
  const peer = req.socket.remoteAddress ?? 'unknown';
  const loopback = peer === '127.0.0.1' || peer === '::1' || peer === '::ffff:127.0.0.1';
  const header = trustedHeader ?? 'x-real-ip';
  const real = req.headers[header];
  if ((loopback || trustedHeader) && typeof real === 'string' && real.trim() && real.length <= 64) return real.trim();
  return peer;
}

/** Minimal fixed-window per-IP rate limit for the internet-facing POSTs. */
class RateLimit {
  private hits = new Map<string, { n: number; resetAt: number }>();
  constructor(private max = 30, private windowMs = 60_000) {}
  allow(ip: string, nowMs = Date.now()): boolean {
    const h = this.hits.get(ip);
    if (!h || h.resetAt <= nowMs) {
      if (this.hits.size > 10_000) this.hits.clear(); // bound memory
      this.hits.set(ip, { n: 1, resetAt: nowMs + this.windowMs });
      return true;
    }
    h.n += 1;
    return h.n <= this.max;
  }
}

export class HomeNode {
  readonly issuer: IssuerKey;
  readonly principals: PrincipalStore;
  readonly invites: InviteStore;
  readonly roles: JsonStore<RolesConfig>;
  readonly audiences: JsonStore<AudiencesConfig>;
  /** What console invites carry — the deployment's policy (policy.ts). */
  readonly invitePolicy: JsonStore<InvitePolicy>;
  readonly mintLog: MintLog;
  readonly accounts: AccountStore;
  readonly codes: CodeStore;
  /** Ticket holders (tickets.ts) and what a ticket grants by default. */
  readonly tickets: TicketStore;
  readonly ticketDefaults: JsonStore<TicketDefaults>;
  /** What the node calls itself for people (config/site.json). */
  readonly site: JsonStore<SiteInfo>;
  /** Sign-in sessions (sessions.ts). */
  readonly sessions: SessionStore;
  /** Null = email sign-in off. */
  readonly email: EmailSender | null;
  readonly human: HumanAuth;
  private limiter = new RateLimit();
  /** The ticket site's calls come from one server in bursts: their own, wider window. */
  private ticketsLimiter = new RateLimit(120, 60_000);
  private server = createServer((req, res) => void this.route(req, res));

  constructor(readonly cfg: ServerConfig, opts: { fetchImpl?: FetchLike; email?: EmailSender } = {}) {
    this.issuer = loadOrCreateIssuerKey(join(cfg.dataDir, 'issuer-key.pem'));
    this.principals = new PrincipalStore(join(cfg.dataDir, 'principals.json'));
    this.invites = new InviteStore(join(cfg.dataDir, 'invites.json'));
    this.roles = rolesStore(join(cfg.configDir, 'roles.json'));
    this.audiences = audiencesStore(join(cfg.configDir, 'audiences.json'));
    this.invitePolicy = invitePolicyStore(join(cfg.configDir, 'invite-policy.json'));
    this.mintLog = new MintLog(join(cfg.dataDir, 'minted.jsonl'));
    this.accounts = new AccountStore(join(cfg.dataDir, 'accounts.json'));
    this.codes = new CodeStore(join(cfg.dataDir, 'codes.json'));
    this.tickets = new TicketStore(join(cfg.dataDir, 'tickets.json'));
    this.ticketDefaults = ticketDefaultsStore(join(cfg.configDir, 'ticket-defaults.json'));
    this.site = siteStore(join(cfg.configDir, 'site.json'));
    this.sessions = new SessionStore(join(cfg.dataDir, 'sessions.json'));
    if (cfg.ticketsToken !== undefined && cfg.ticketsToken.length < 32) {
      throw new Error('HN_TICKETS_TOKEN must be at least 32 characters (e.g. openssl rand -base64 32)');
    }
    this.email = opts.email ?? emailSenderFromConfig(cfg, opts.fetchImpl);
    this.human = new HumanAuth({
      codes: this.codes,
      tickets: this.tickets,
      ticketDefaults: this.ticketDefaults,
      email: this.email,
      cfg,
      issuer: this.issuer,
      accounts: this.accounts,
      principals: this.principals,
      roles: this.roles,
      audiences: this.audiences,
      mintLog: this.mintLog,
      invitePolicy: this.invitePolicy,
      allow: (ip) => this.limiter.allow(ip),
      fetchImpl: opts.fetchImpl,
      site: this.site,
      invites: this.invites,
      sessions: this.sessions,
    });
  }

  private exchangeDeps(): ExchangeDeps {
    return {
      issuer: this.issuer,
      iss: this.cfg.iss,
      principals: this.principals,
      invites: this.invites,
      mintLog: this.mintLog,
      knownAudiences: () => Object.keys(this.audiences.get()),
      nameTaken: (n) => this.accounts.nameTaken(n),
    };
  }

  /** Resolves with the bound port (useful with port 0 in tests). */
  start(): Promise<number> {
    for (const s of [this.principals, this.invites, this.roles, this.audiences, this.site, this.invitePolicy, this.accounts, this.codes, this.tickets, this.ticketDefaults]) s.startWatching();
    return new Promise((resolve) =>
      this.server.listen(this.cfg.port, this.cfg.bind, () => {
        const addr = this.server.address();
        const port = typeof addr === 'object' && addr ? addr.port : this.cfg.port;
        console.error(`[hn] home node for ${this.cfg.iss} on ${this.cfg.bind}:${port} — issuer ${this.issuer.id}`);
        if (!this.cfg.discordClientId) console.error('[hn] DISCORD_CLIENT_ID unset — Discord login off (username/passkey login still on)');
        if (!this.cfg.googleClientId) console.error('[hn] GOOGLE_CLIENT_ID unset — Google login off');
        if (!this.email) console.error('[hn] EMAIL_PROVIDER unset — email sign-in off');
        if (!this.cfg.ticketsToken) console.error('[hn] HN_TICKETS_TOKEN unset — the /tickets API is off');
        else if (!this.email) console.error('[hn] note: the /tickets API is on, but with no email sign-in nobody can use a ticket');
        if ((this.email || this.cfg.ticketsToken) && !this.ticketDefaults.get().configured) {
          console.error('[hn] no config/ticket-defaults.json — no ticket can be made until there is one');
        }
        if (!this.invitePolicy.get().configured) console.error('[hn] no config/invite-policy.json — the sponsor console is off');
        resolve(port);
      }),
    );
  }

  stop(): void {
    this.server.close();
    this.principals.stopWatching();
    this.invites.stopWatching();
    this.roles.stopWatching();
    this.audiences.stopWatching();
    this.invitePolicy.stopWatching();
    this.accounts.stopWatching();
    this.codes.stopWatching();
    this.tickets.stopWatching();
    this.ticketDefaults.stopWatching();
  }

  // ── routing ──

  private async route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const ip = clientIp(req, this.cfg.clientIpHeader);
    try {
      if (req.method === 'GET' && url.pathname === '/.well-known/mcpl-identity') {
        return json(res, 200, { scheme: 'ed25519', domain: this.cfg.iss, publicKey: this.issuer.id });
      }
      if (req.method === 'GET' && url.pathname === '/healthz') {
        return json(res, 200, { ok: true, principals: this.principals.all().length });
      }
      if (req.method === 'GET' && url.pathname === '/services') {
        // The service directory. Hosts resolve audience → API base from here
        // at runtime, so a new archipelago service is reachable as soon as it
        // lands in audiences.json (hot-reloaded) — no host restart, no recipe
        // edit, nothing compiled in.
        //
        // Deliberately unauthenticated and NOT a permission statement: these
        // are public base URLs. Whether a given principal may actually use one
        // is still decided where it was always decided — at POST /token, which
        // refuses an audience the principal isn't allowed.
        // `mcpl` is the same directory for the other seam: audience → MCPL
        // endpoint (wss), so a host can dial a service by audience name
        // (`mcpl_deploy {access}` with no url) and never hold an address.
        const audiences = this.audiences.get();
        return json(res, 200, { home: this.cfg.iss, services: serviceDirectory(audiences), mcpl: mcplDirectory(audiences) });
      }
      if (req.method === 'GET' && url.pathname === '/agents.md') {
        // The door explains itself: everything a non-Connectome agent (or its
        // operator) needs to enroll and connect, without a human walkthrough.
        return markdown(res, agentsGuide(this.cfg.configDir));
      }
      if (await this.human.route(req, url, res, ip)) return;
      if (url.pathname === '/tickets' || url.pathname.startsWith('/tickets/')) {
        if (!this.ticketsLimiter.allow(ip)) return json(res, 429, { error: 'rate limited' });
        return await this.ticketsApi(req, url, res);
      }
      if (req.method === 'GET' && url.pathname === '/enroll') {
        // the URL an invite hands an agent is opened in a browser too: say what it's for
        return html(res, 200, enrollPage({ site: this.site.get(), iss: this.cfg.iss, publicUrl: this.cfg.publicUrl }));
      }
      if (url.pathname.startsWith('/console')) {
        if (!this.limiter.allow(ip)) return json(res, 429, { error: 'rate limited' });
        if (await this.consoleRoute(req, url, res)) return;
      }
      if (req.method === 'POST' && (url.pathname === '/token' || url.pathname === '/enroll')) {
        if (!this.limiter.allow(ip)) return json(res, 429, { error: 'rate limited' });
        const body = await readJson(req);
        const result =
          url.pathname === '/token'
            ? handleTokenRequest(body, this.exchangeDeps())
            : handleEnroll(body, this.exchangeDeps());
        return json(res, result.status, result.body);
      }
      if (req.method === 'GET' && url.pathname === '/') {
        return html(res, 200, homePage({ site: this.site.get(), iss: this.cfg.iss, issuerId: this.issuer.id, audiences: this.audiences.get() }));
      }
      json(res, 404, { error: 'not found' });
    } catch (err) {
      console.error(`[hn] ${req.method} ${url.pathname} error: ${(err as Error).message}`);
      json(res, 500, { error: 'internal error' });
    }
  }

  // ── the ticket site's API (tickets.ts) ──

  /**
   * The ticket site has verified the payment and holds the address; it tells
   * this node who may sign up, and mints invites for the agents its holders
   * run. Bearer HN_TICKETS_TOKEN, compared in constant time; without the
   * token configured the routes don't exist.
   *
   *   POST   /tickets                 {email, ref, name?, note?, scopes?, audiences?} → 201 made, 200 known
   *   GET    /tickets/<email>         {held, claimedBy?, addedAt?}
   *   DELETE /tickets/<email>         204 — a refund: what the ticket gave goes (its account's copy,
   *                                   its unclaimed invites, its agents' grants); the identities stay
   *   POST   /tickets/invites         {email, ref, agentName?} → 201 {code, enrolUrl, expiresAt, agentsMd}
   *   GET    /tickets/invites?email=…|ref=…
   *   DELETE /tickets/invites/<code>  204 — revoke an unclaimed invite of a ticket
   */
  private async ticketsApi(req: IncomingMessage, url: URL, res: ServerResponse): Promise<void> {
    const token = this.cfg.ticketsToken;
    if (!token) return json(res, 404, { error: 'not found' });
    const m = /^bearer (.+)$/i.exec(req.headers.authorization ?? '');
    if (!m || !constantEqual(m[1]!, token)) return json(res, 401, { error: 'unauthorized' });
    const { tickets } = this;
    if (url.pathname === '/tickets/invites' || url.pathname.startsWith('/tickets/invites/')) return this.ticketInvites(req, url, res);
    if (req.method === 'POST' && url.pathname === '/tickets') {
      const b = ((await readJson(req)) ?? {}) as Record<string, unknown>;
      const email = clean(b.email, 254);
      const ref = clean(b.ref, 200);
      const name = clean(b.name, 32);
      const note = clean(b.note, 120);
      const list = (v: unknown, what: string): string[] | undefined | null => {
        if (v === undefined) return undefined;
        return Array.isArray(v) && v.every((s) => typeof s === 'string' && s.length > 0) ? [...new Set(v as string[])] : (json(res, 400, { error: `${what} must be a list of strings` }), null);
      };
      if (!usableEmail(email)) return json(res, 400, { error: 'email must be an address (printable ASCII)' });
      if (!ref) return json(res, 400, { error: 'ref required (the ticket site’s reference for this purchase)' });
      const scopes = list(b.scopes, 'scopes');
      if (scopes === null) return;
      const audiences = list(b.audiences, 'audiences');
      if (audiences === null) return;
      const known = tickets.byRef(ref);
      if (known) return json(res, 200, { ticket: ticketView(known), created: false });
      if (tickets.removed(ref)) return json(res, 410, { error: 'removed', ref });
      const d = this.ticketDefaults.get();
      if (!d.configured) return json(res, 503, { error: `no ticket can be made: ${noDefaultsMessage(this.cfg.configDir)}` });
      const grant = { audiences: audiences ?? d.audiences, scopes: scopes ?? d.scopes };
      const bad = ticketGrantProblem(d, Object.keys(this.audiences.get()), grant.audiences, grant.scopes);
      if (bad) return json(res, 400, { error: bad });
      // the holder's name goes through what a person picking one must
      const nameOk = Boolean(name) && !nameProblem(name, this.accounts, (n) => this.principals.nameTaken(n), '');
      const named = nameOk ? { name } : {};
      const r = tickets.add({ email, source: `api:${ref}`, ...grant, ...named, ...(note ? { note } : {}) });
      if (!r.created) {
        // the mailbox already holds one (a second purchase): keep the first,
        // remember this ref, and let the new purchase widen the grant — on
        // the account too, if the ticket is taken up
        const t = tickets.addRef(email, ref, { ...(audiences ? { audiences } : {}), ...(scopes ? { scopes } : {}), ...named }) ?? r.ticket;
        if (t.claimedBy) this.syncTicketGrant(t);
        console.error(`[hn] tickets api: ${maskEmail(email)} already holds a ticket — recorded ref ${ref}`);
        return json(res, 200, { ticket: ticketView(t), created: false, ...(name ? { nameAccepted: nameOk } : {}) });
      }
      console.error(`[hn] tickets api: ticket ${r.ticket.id} added for ${maskEmail(email)} (${ref}) → ${r.ticket.audiences.join(', ')}`);
      return json(res, 201, { ticket: ticketView(r.ticket), created: true, ...(name ? { nameAccepted: nameOk } : {}) });
    }
    const em = /^\/tickets\/(.+)$/.exec(url.pathname);
    let email = '';
    try {
      email = decodeURIComponent(em?.[1] ?? '');
    } catch {
      /* malformed escape: not an address */
    }
    if (!em || !usableEmail(email)) return json(res, req.method === 'GET' || req.method === 'DELETE' ? 400 : 404, { error: 'not an address' });
    if (req.method === 'GET') {
      const t = tickets.byEmail(email);
      return json(res, 200, t ? { held: true, addedAt: t.addedAt, ...(t.claimedBy ? { claimedBy: t.claimedBy } : {}) } : { held: false });
    }
    if (req.method === 'DELETE') {
      const t = tickets.byEmail(email);
      // What the ticket gave goes FIRST; only then the ticket. A failure
      // here (a held lock, a full disk) leaves the ticket to retry against.
      // Without a ticket, a stray copy on an account is still taken back.
      let back: ReturnType<typeof takeBackTicket>;
      try {
        back = takeBackTicket(t ?? { id: '', email }, { accounts: this.accounts, invites: this.invites, principals: this.principals });
      } catch (err) {
        console.error(`[hn] tickets api: refund of ${maskEmail(email)} failed: ${(err as Error).message}`);
        return json(res, 500, { error: 'could not take the ticket’s grant back — try again' });
      }
      if (!t) {
        if (!back.accounts) return json(res, 404, { error: 'no ticket for that address' });
        console.error(`[hn] tickets api: no ticket for ${maskEmail(email)}, but a stray copy on ${back.accounts} account(s) taken back`);
      } else {
        tickets.remove(email);
        console.error(`[hn] tickets api: ticket ${t.id} removed for ${maskEmail(email)} — taken back from ${back.accounts} account(s), ${back.invites} unclaimed invite(s), ${back.agents} agent(s)`);
      }
      res.writeHead(204);
      res.end();
      return;
    }
    json(res, 404, { error: 'not found' });
  }

  /** The ticket's grant as it is now, onto the account that took it up. */
  private syncTicketGrant(t: Ticket): void {
    if (!t.claimedBy) return;
    const claimedAt = t.claimedAt ?? new Date().toISOString();
    this.accounts.update(t.claimedBy, (a) => ({ ...a, ticket: { email: t.email, source: t.source, claimedAt: a.ticket?.claimedAt ?? claimedAt, audiences: [...t.audiences], scopes: [...t.scopes] } }));
  }

  /** Who vouches for an agent minted from this ticket: the account that
   *  took it up, else a stable placeholder for the ticket until someone does.
   *  The sponsor's scopes are the ticket's — delegation stays within them. */
  private ticketSponsor(t: Ticket): { sponsor: SponsorIdentity; disabled: boolean } {
    const acct = t.claimedBy ? this.accounts.bySub(t.claimedBy) : undefined;
    if (acct) {
      return { disabled: Boolean(acct.disabled), sponsor: { sub: acct.sub, name: displayName(acct), scopes: [...t.scopes], ...(acct.withhold ? { withhold: acct.withhold } : {}) } };
    }
    return { disabled: false, sponsor: { sub: ticketPlaceholderSub(t), name: t.name || TICKET_HOLDER_NAME, scopes: [...t.scopes] } };
  }

  /** The ticket `email` and/or `ref` name — both, when both are given, must
   *  name the same one. Also a refunded ticket, for the listing. */
  private ticketFor(email: string, ref: string): { live?: Ticket; gone?: RemovedTicket } | null {
    const byEmail = usableEmail(email) ? this.tickets.byEmail(email) : undefined;
    const byRef = ref ? this.tickets.byRef(ref) : undefined;
    if (email && ref && byEmail && byRef && byEmail.id !== byRef.id) return null;
    if (usableEmail(email) && ref && ((byEmail && !byRef) || (byRef && !byEmail))) {
      // one of them names a ticket, the other doesn't: not the same ticket
      const live = byEmail ?? byRef!;
      if (!(byRef || live.refs?.includes(ref) || live.source === `api:${ref}`) || !(byEmail || emailKey(live.email) === emailKey(email))) return null;
    }
    const live = byEmail ?? byRef;
    if (live) return { live };
    const gone = this.tickets.removedTicket({ ...(usableEmail(email) ? { email } : {}), ...(ref ? { ref } : {}) });
    return gone ? { gone } : null;
  }

  private async ticketInvites(req: IncomingMessage, url: URL, res: ServerResponse): Promise<void> {
    const code = /^\/tickets\/invites\/(.+)$/.exec(url.pathname)?.[1];
    if (code !== undefined) {
      if (req.method !== 'DELETE') return json(res, 404, { error: 'not found' });
      const inv = this.invites.all().find((i) => i.code === decodeURIComponent(code) && i.ticket);
      if (!inv || (inv.uses ?? 0) >= (inv.maxUses ?? 1)) return json(res, 404, { error: 'no such unclaimed invite' });
      this.invites.revoke(inv.code);
      console.error(`[hn] tickets api: invite ${inv.code} of ticket ${inv.ticket} revoked`);
      res.writeHead(204);
      res.end();
      return;
    }
    if (req.method === 'POST') {
      const b = ((await readJson(req)) ?? {}) as Record<string, unknown>;
      const email = clean(b.email, 254);
      const ref = clean(b.ref, 200);
      const agentName = clean(b.agentName, 60);
      const found = this.ticketFor(email, ref);
      const t = found?.live;
      if (!t) return json(res, 404, { error: 'no_ticket' });
      const d = this.ticketDefaults.get();
      if (!d.configured) return json(res, 503, { error: `no invite can be made: ${noDefaultsMessage(this.cfg.configDir)}` });
      const { sponsor, disabled } = this.ticketSponsor(t);
      if (disabled) return json(res, 403, { error: 'account disabled' });
      // ever minted for this ticket — claimed, revoked, expired all count
      if ((t.invitesMinted ?? 0) >= d.invites.lifetime) return json(res, 409, { error: 'budget', reason: 'lifetime' });
      const r = mintSponsoredInvite(this.invites, this.invitePolicy.get(), sponsor, agentName || undefined, {
        gate: false, knownAudiences: Object.keys(this.audiences.get()),
        // the ticket's own reach, whatever the policy's rules would add
        restrict: { audiences: t.audiences, scopes: [...new Set([...t.scopes, ...d.allowed.scopes])] },
        budget: { active: d.invites.active }, sponsorSubs: ticketSponsorSubs(t), ticket: t.id,
      });
      if (!r.ok) return json(res, r.status === 429 ? 409 : r.status, r.status === 429 ? { error: 'budget', reason: r.budget } : { error: r.error });
      this.tickets.countInvite(t.id);
      this.mintLog.append({
        at: new Date().toISOString(), sub: sponsor.sub, aud: 'console',
        scopes: r.invite.scopes, exp: Math.floor(Date.parse(r.invite.expiresAt!) / 1000), by: 'tickets',
      });
      console.error(`[hn] tickets api: ${sponsor.sub} (${sponsor.name}) minted invite ${r.invite.code} for ticket ${t.id} [${r.invite.scopes.join(' ')}] → ${r.invite.audiences!.join(', ')}`);
      return json(res, 201, {
        code: r.invite.code, enrolUrl: `${this.cfg.publicUrl}/enroll`, expiresAt: r.invite.expiresAt, agentsMd: `${this.cfg.publicUrl}/agents.md`,
      });
    }
    if (req.method === 'GET') {
      const found = this.ticketFor(clean(url.searchParams.get('email'), 254), clean(url.searchParams.get('ref'), 200));
      const t = found?.live ?? found?.gone;
      if (!t) return json(res, 404, { error: 'no_ticket' });
      const subs = ticketSponsorSubs(t);
      const invites = this.invites.all().filter((i) => i.ticket === t.id || (i.sponsor && subs.includes(i.sponsor) && !i.ticket)).map((i) => {
        const claimed = (i.uses ?? 0) >= (i.maxUses ?? 1);
        const enrolled = claimed ? this.principals.all().find((p) => p.notes?.includes(`invite ${i.code}`)) : undefined;
        return {
          ...(claimed ? {} : { code: i.code }),
          createdAt: i.createdAt ?? null, expiresAt: i.expiresAt ?? null,
          ...(enrolled ? { claimedBy: enrolled.sub } : {}),
          ...(i.label ? { agentName: i.label } : {}),
        };
      });
      return json(res, 200, { invites, ...(found?.gone ? { refunded: true, removedAt: found.gone.removedAt } : {}) });
    }
    json(res, 404, { error: 'not found' });
  }

  // ── sponsor console (see console.ts header for the design) ──

  /** Offline-verify a Bearer console token; null (+401 written) on failure.
   *  The scopes it must carry are the invite policy's console gate. */
  private consoleAuth(req: IncomingMessage, res: ServerResponse): Aid1Payload | null {
    const gate = consoleRequiredScopes(this.invitePolicy.get());
    if (gate === null) {
      json(res, 503, { error: 'this home has no invite policy (config/invite-policy.json), so the console is off' });
      return null;
    }
    const m = /^Bearer (.+)$/.exec(req.headers.authorization ?? '');
    const v = m
      ? verifyToken(m[1]!, { issuerId: this.issuer.id, iss: this.cfg.iss, aud: 'console', requireScopes: gate })
      : ({ ok: false, reason: 'no bearer token' } as const);
    if (!v.ok) {
      json(res, 401, { error: v.reason });
      return null;
    }
    return v.payload;
  }

  private async consoleRoute(req: IncomingMessage, url: URL, res: ServerResponse): Promise<boolean> {
    if (url.pathname === '/console' && req.method === 'GET') {
      // the console's page is part of /account now; its API below stays for scripts
      html(res, 200, consoleMovedPage({ site: this.site.get(), iss: this.cfg.iss }));
      return true;
    }
    if (url.pathname === '/console/me' && req.method === 'GET') {
      const who = this.consoleAuth(req, res);
      if (who) {
        json(res, 200, {
          sub: who.sub, name: who.name,
          delegable: delegableScopes(this.invitePolicy.get(), who.scopes).filter((s) => !this.accounts.bySub(who.sub)?.withhold?.includes(s)),
          canAnchor: who.scopes.includes(ANCHOR_SCOPE), home: this.cfg.iss,
          ...(who.scopes.includes(ANCHOR_SCOPE) ? { residentScopes: residentScopes(this.invitePolicy.get()) } : {}),
        });
      }
      return true;
    }
    if (url.pathname === '/console/invites' && req.method === 'GET') {
      const who = this.consoleAuth(req, res);
      if (who) json(res, 200, { invites: sponsorInviteView(this.invites, this.principals, who.sub) });
      return true;
    }
    if (url.pathname === '/console/invites' && req.method === 'POST') {
      const who = this.consoleAuth(req, res);
      if (!who) return true;
      const body = (await readJson(req)) as { label?: unknown; anchor?: unknown } | null;
      const withhold = this.accounts.bySub(who.sub)?.withhold;
      const r = mintSponsoredInvite(this.invites, this.invitePolicy.get(), { sub: who.sub, name: who.name, scopes: who.scopes, ...(withhold ? { withhold } : {}) },
        typeof body?.label === 'string' ? body.label : undefined,
        { anchorDomain: body?.anchor === true ? this.cfg.iss : null,
          knownAudiences: Object.keys(this.audiences.get()) });
      if (!r.ok) {
        json(res, r.status, { error: r.error });
        return true;
      }
      this.mintLog.append({
        at: new Date().toISOString(), sub: who.sub, aud: 'console',
        scopes: r.invite.scopes, exp: Math.floor(Date.parse(r.invite.expiresAt!) / 1000), by: 'cli',
      });
      console.error(`[hn] console: ${who.sub} (${who.name}) minted invite ${r.invite.code} [${r.invite.scopes.join(' ')}]`);
      json(res, 200, { invite: r.invite });
      return true;
    }
    return false;
  }
}

// ── helpers ──

/** Equal strings, in time that doesn't depend on where they differ. */
function constantEqual(a: string, b: string): boolean {
  const x = createHash('sha256').update(a).digest();
  const y = createHash('sha256').update(b).digest();
  return timingSafeEqual(x, y) && a.length === b.length;
}

/** What the API tells the ticket site about a ticket (it holds the address already). */
function ticketView(t: Ticket): Record<string, unknown> {
  const { note: _n, ...rest } = t;
  return rest;
}


function markdown(res: ServerResponse, body: string): void {
  res.writeHead(200, { 'content-type': 'text/markdown; charset=utf-8', 'cache-control': 'public, max-age=300' });
  res.end(body);
}

/** `<config dir>/agents.md` when the deployment has its own wording (read
 *  on each request, so an edit lands at once), else the repo's
 *  docs/AGENTS.md, loaded once per process — it ships in the repo so the
 *  served guide is versioned with the endpoints it documents. */
let agentsGuideCache: string | null = null;
function agentsGuide(configDir: string): string {
  const own = join(configDir, 'agents.md');
  try {
    if (statSync(own).isFile()) return readFileSync(own, 'utf8');
  } catch {
    /* absent or unreadable: the built-in one */
  }
  if (agentsGuideCache === null) {
    const here = dirname(fileURLToPath(import.meta.url));
    // src/ layout in dev (tsx/bun), dist/src/ when built — walk up to repo root.
    for (const rel of ['../docs/AGENTS.md', '../../docs/AGENTS.md']) {
      try {
        agentsGuideCache = readFileSync(join(here, rel), 'utf8');
        break;
      } catch {
        /* try next */
      }
    }
    agentsGuideCache ??= '# agents.md\n\nGuide missing from this deployment — ask the operator.\n';
  }
  return agentsGuideCache;
}
