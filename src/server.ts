/**
 * The home node HTTP service (docs/home-node.md §3). Plain node:http —
 * five routes, no framework. TLS is the fronting proxy's job
 * (caddy/tailscale-serve); default bind is loopback.
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadOrCreateIssuerKey, type IssuerKey } from './keys.js';
import { mintToken, newJti, type Aid1Payload } from './token.js';
import { handleEnroll, handleTokenRequest, type ExchangeDeps } from './exchange.js';
import { authorizeUrl, completeOAuth, displayNameOf, oauthScopes } from './oauth.js';
import {
  audiencesStore,
  grantForRoles,
  InviteStore,
  MintLog,
  PrincipalStore,
  rolesStore,
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

const LOGIN_TOKEN_TTL_MS = 10 * 60_000;
const STATE_TTL_MS = 10 * 60_000;
const BODY_LIMIT = 64 * 1024;

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
  private states = new Map<string, { audience: string; exp: number }>();
  private limiter = new RateLimit();
  private server = createServer((req, res) => void this.route(req, res));

  constructor(readonly cfg: ServerConfig) {
    this.issuer = loadOrCreateIssuerKey(join(cfg.dataDir, 'issuer-key.pem'));
    this.principals = new PrincipalStore(join(cfg.dataDir, 'principals.json'));
    this.invites = new InviteStore(join(cfg.dataDir, 'invites.json'));
    this.roles = rolesStore(join(cfg.configDir, 'roles.json'));
    this.audiences = audiencesStore(join(cfg.configDir, 'audiences.json'));
    this.mintLog = new MintLog(join(cfg.dataDir, 'minted.jsonl'));
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

  start(): void {
    for (const s of [this.principals, this.invites, this.roles, this.audiences]) s.startWatching();
    this.server.listen(this.cfg.port, this.cfg.bind, () => {
      console.error(
        `[hn] home node for ${this.cfg.iss} on ${this.cfg.bind}:${this.cfg.port} — issuer ${this.issuer.id}`,
      );
      if (!this.cfg.discordClientId) console.error('[hn] DISCORD_CLIENT_ID unset — human login disabled');
    });
  }

  stop(): void {
    this.server.close();
    this.principals.stopWatching();
    this.invites.stopWatching();
    this.roles.stopWatching();
    this.audiences.stopWatching();
  }

  // ── routing ──

  private async route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const ip = req.socket.remoteAddress ?? 'unknown';
    try {
      if (req.method === 'GET' && url.pathname === '/.well-known/mcpl-identity') {
        return json(res, 200, { scheme: 'ed25519', domain: this.cfg.iss, publicKey: this.issuer.id });
      }
      if (req.method === 'GET' && url.pathname === '/healthz') {
        return json(res, 200, { ok: true, principals: this.principals.all().length });
      }
      if (req.method === 'GET' && url.pathname === '/agents.md') {
        // The door explains itself: everything a non-Connectome agent (or its
        // operator) needs to enroll and connect, without a human walkthrough.
        return markdown(res, agentsGuide());
      }
      if (req.method === 'GET' && url.pathname === '/login') return this.login(url, res, ip);
      if (req.method === 'GET' && url.pathname === '/oauth/callback') return await this.callback(url, res, ip);
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
<p>An agent arriving from outside? Start with <a href="/agents.md">/agents.md</a>.</p>`));
      }
      json(res, 404, { error: 'not found' });
    } catch (err) {
      console.error(`[hn] ${req.method} ${url.pathname} error: ${(err as Error).message}`);
      json(res, 500, { error: 'internal error' });
    }
  }

  // ── human leg ──

  private login(url: URL, res: ServerResponse, ip: string): void {
    if (!this.limiter.allow(ip)) return json(res, 429, { error: 'rate limited' });
    const audience = url.searchParams.get('audience') ?? '';
    if (!this.audiences.get()[audience]) {
      return html(res, 400, page('unknown audience', `<p>Unknown audience <code>${esc(audience)}</code>.</p>`));
    }
    if (!this.cfg.discordClientId) {
      return html(res, 503, page('login unavailable', '<p>Discord login is not configured on this node.</p>'));
    }
    const state = randomBytes(24).toString('base64url');
    const now = Date.now();
    for (const [k, v] of this.states) if (v.exp <= now) this.states.delete(k);
    this.states.set(state, { audience, exp: now + STATE_TTL_MS });
    redirect(
      res,
      authorizeUrl(
        this.cfg.discordClientId,
        `${this.cfg.publicUrl}/oauth/callback`,
        state,
        oauthScopes(Boolean(this.cfg.discordBotToken)),
      ),
    );
  }

  private async callback(url: URL, res: ServerResponse, ip: string): Promise<void> {
    if (!this.limiter.allow(ip)) return json(res, 429, { error: 'rate limited' });
    const state = url.searchParams.get('state') ?? '';
    const code = url.searchParams.get('code') ?? '';
    const st = this.states.get(state);
    this.states.delete(state); // single-use, success or not
    if (!st || st.exp <= Date.now()) {
      return html(res, 400, page('login expired', '<p>Login attempt expired or invalid — start again from the service.</p>'));
    }
    if (!code || !this.cfg.discordClientId || !this.cfg.discordClientSecret) {
      return html(res, 400, page('login failed', '<p>Discord did not complete the login.</p>'));
    }

    const { user, member } = await completeOAuth({
      clientId: this.cfg.discordClientId,
      clientSecret: this.cfg.discordClientSecret,
      redirectUri: `${this.cfg.publicUrl}/oauth/callback`,
      code,
      guildId: this.roles.get().guildId,
      botToken: this.cfg.discordBotToken,
    });

    const grant = member ? grantForRoles(member.roles, this.roles.get()) : null;
    const needed = this.audiences.get()[st.audience]?.requiredScopes ?? [];
    const missing = grant ? needed.filter((s) => !grant.scopes.includes(s)) : needed;
    if (!grant || missing.length) {
      const why = !member ? 'not in guild' : !grant ? 'no qualifying role' : `missing ${missing.join(', ')} for ${st.audience}`;
      console.error(`[hn] login refused: discord:${user.id} (${user.username}) — ${why}`);
      return html(res, 403, page('no access', `<p>Hi <b>${esc(displayNameOf(user, member))}</b> — your Discord account
doesn't have a role that grants access to <b>${esc(st.audience)}</b>${member ? '' : ' (you are not in the guild)'}. Ask an operator for access, then try again.</p>`));
    }

    const nowMs = Date.now();
    const payload: Aid1Payload = {
      v: 1,
      iss: this.cfg.iss,
      sub: `human:discord:${user.id}`,
      kind: 'human',
      name: displayNameOf(user, member),
      aud: st.audience,
      scopes: grant.scopes,
      ...(grant.claims ? { claims: grant.claims } : {}),
      iat: Math.floor(nowMs / 1000),
      exp: Math.floor((nowMs + LOGIN_TOKEN_TTL_MS) / 1000),
      jti: newJti(),
    };
    const token = mintToken(this.issuer.privateKey, payload);
    this.mintLog.append({
      at: new Date(nowMs).toISOString(),
      jti: payload.jti,
      sub: payload.sub,
      aud: payload.aud,
      scopes: payload.scopes,
      exp: payload.exp,
      by: 'oauth',
    });
    console.error(`[hn] login: ${payload.sub} (${payload.name}) → ${payload.aud} [${payload.scopes.join(' ')}]`);
    // Token rides the fragment — never hits logs or Referer headers (§8).
    redirect(res, `${this.audiences.get()[st.audience]!.redirect}#token=${token}`);
  }
}

// ── tiny http helpers ──

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

function html(res: ServerResponse, status: number, body: string): void {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' });
  res.end(body);
}

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

function redirect(res: ServerResponse, to: string): void {
  res.writeHead(302, { location: to });
  res.end();
}

function page(title: string, body: string): string {
  return `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<style>body{font:16px/1.5 system-ui;max-width:36rem;margin:15vh auto;padding:0 1rem;color:#222}
code{background:#f2f2f2;padding:.1em .3em;border-radius:4px;word-break:break-all}
@media(prefers-color-scheme:dark){body{background:#111;color:#ddd}code{background:#222}}</style>
<h2>${esc(title)}</h2>${body}`;
}

function esc(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!);
}

function readJson(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > BODY_LIMIT) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        resolve(null); // handlers reject malformed bodies with a reason
      }
    });
    req.on('error', reject);
  });
}

