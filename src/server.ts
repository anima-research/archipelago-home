/**
 * The home node HTTP service (docs/home-node.md §3). Plain node:http, no
 * framework. TLS is the fronting proxy's job (caddy/tailscale-serve);
 * default bind is loopback. The human sign-in routes live in human.ts.
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadOrCreateIssuerKey, type IssuerKey } from './keys.js';
import { verifyToken, type Aid1Payload } from './token.js';
import { handleEnroll, handleTokenRequest, type ExchangeDeps } from './exchange.js';
import { ANCHOR_SCOPE, consolePage, delegableScopes, mintSponsoredInvite, sponsorInviteView } from './console.js';
import { AccountStore } from './accounts.js';
import { HumanAuth } from './human.js';
import type { FetchLike } from './oauth.js';
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
  };
}

/**
 * The client address for rate limiting. Behind the local reverse proxy every
 * request arrives from loopback, which would put the whole internet in one
 * bucket; the proxy overwrites X-Real-IP with the real client, so it is trusted
 * only when the connection itself comes from loopback.
 */
export function clientIp(req: Pick<IncomingMessage, 'headers' | 'socket'>): string {
  const peer = req.socket.remoteAddress ?? 'unknown';
  const loopback = peer === '127.0.0.1' || peer === '::1' || peer === '::ffff:127.0.0.1';
  const real = req.headers['x-real-ip'];
  if (loopback && typeof real === 'string' && real.trim() && real.length <= 64) return real.trim();
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
  readonly mintLog: MintLog;
  readonly accounts: AccountStore;
  readonly human: HumanAuth;
  private limiter = new RateLimit();
  private server = createServer((req, res) => void this.route(req, res));

  constructor(readonly cfg: ServerConfig, opts: { fetchImpl?: FetchLike } = {}) {
    this.issuer = loadOrCreateIssuerKey(join(cfg.dataDir, 'issuer-key.pem'));
    this.principals = new PrincipalStore(join(cfg.dataDir, 'principals.json'));
    this.invites = new InviteStore(join(cfg.dataDir, 'invites.json'));
    this.roles = rolesStore(join(cfg.configDir, 'roles.json'));
    this.audiences = audiencesStore(join(cfg.configDir, 'audiences.json'));
    this.mintLog = new MintLog(join(cfg.dataDir, 'minted.jsonl'));
    this.accounts = new AccountStore(join(cfg.dataDir, 'accounts.json'));
    this.human = new HumanAuth({
      cfg,
      issuer: this.issuer,
      accounts: this.accounts,
      principals: this.principals,
      roles: this.roles,
      audiences: this.audiences,
      mintLog: this.mintLog,
      allow: (ip) => this.limiter.allow(ip),
      fetchImpl: opts.fetchImpl,
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
    };
  }

  /** Resolves with the bound port (useful with port 0 in tests). */
  start(): Promise<number> {
    for (const s of [this.principals, this.invites, this.roles, this.audiences, this.accounts]) s.startWatching();
    return new Promise((resolve) =>
      this.server.listen(this.cfg.port, this.cfg.bind, () => {
        const addr = this.server.address();
        const port = typeof addr === 'object' && addr ? addr.port : this.cfg.port;
        console.error(`[hn] home node for ${this.cfg.iss} on ${this.cfg.bind}:${port} — issuer ${this.issuer.id}`);
        if (!this.cfg.discordClientId) console.error('[hn] DISCORD_CLIENT_ID unset — Discord login off (username/passkey login still on)');
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
    this.accounts.stopWatching();
  }

  // ── routing ──

  private async route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const ip = clientIp(req);
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
        return markdown(res, agentsGuide());
      }
      if (await this.human.route(req, url, res, ip)) return;
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
        return html(res, 200, page('archipelago home', `<p>Identity home node for <b>${esc(this.cfg.iss)}</b>.</p>
<p>Issuer key: <code>${esc(this.issuer.id)}</code></p>
<p>Services log you in via <code>/login?audience=…</code>; agents exchange key proofs at <code>/token</code>.</p>
<p>People: manage your username, password, two-factor code and passkeys at <a href="/account">/account</a>.</p>
<p>An agent arriving from outside? Start with <a href="/agents.md">/agents.md</a>.</p>`));
      }
      json(res, 404, { error: 'not found' });
    } catch (err) {
      console.error(`[hn] ${req.method} ${url.pathname} error: ${(err as Error).message}`);
      json(res, 500, { error: 'internal error' });
    }
  }

  // ── sponsor console (see console.ts header for the design) ──

  /** Offline-verify a Bearer console token; null (+401 written) on failure. */
  private consoleAuth(req: IncomingMessage, res: ServerResponse): Aid1Payload | null {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization ?? '');
    const v = m
      ? verifyToken(m[1]!, { issuerId: this.issuer.id, iss: this.cfg.iss, aud: 'console', requireScopes: ['worlds:join'] })
      : ({ ok: false, reason: 'no bearer token' } as const);
    if (!v.ok) {
      json(res, 401, { error: v.reason });
      return null;
    }
    return v.payload;
  }

  private async consoleRoute(req: IncomingMessage, url: URL, res: ServerResponse): Promise<boolean> {
    if (url.pathname === '/console' && req.method === 'GET') {
      html(res, 200, consolePage(this.cfg.iss));
      return true;
    }
    if (url.pathname === '/console/me' && req.method === 'GET') {
      const who = this.consoleAuth(req, res);
      if (who) {
        json(res, 200, {
          sub: who.sub, name: who.name, delegable: delegableScopes(who.scopes),
          canAnchor: who.scopes.includes(ANCHOR_SCOPE), home: this.cfg.iss,
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
      const r = mintSponsoredInvite(this.invites, { sub: who.sub, name: who.name, scopes: who.scopes },
        typeof body?.label === 'string' ? body.label : undefined,
        { anchorDomain: body?.anchor === true ? this.cfg.iss : null });
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

function markdown(res: ServerResponse, body: string): void {
  res.writeHead(200, { 'content-type': 'text/markdown; charset=utf-8', 'cache-control': 'public, max-age=300' });
  res.end(body);
}

/** docs/AGENTS.md, loaded once per process (fresh on restart, cheap always).
 *  Ships in the repo so the served guide is versioned with the endpoints it
 *  documents. */
let agentsGuideCache: string | null = null;
function agentsGuide(): string {
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
