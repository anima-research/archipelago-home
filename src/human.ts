/**
 * The human leg: every way a person gets an aid1 login token, and the page
 * where they manage those ways.
 *
 *   GET  /login?audience=…        chooser: Discord · Google · username+password · passkey
 *   GET  /login/discord?state=…   → Discord OAuth (`?via=discord` on /login skips the chooser)
 *   GET  /oauth/callback          Discord's return leg (also: linking Discord to an account)
 *   GET  /login/google?state=…    → Google OIDC (`?via=google` skips the chooser)
 *   GET  /oauth/google/callback   Google's return leg (also: linking Google; claiming an invite)
 *   POST /login/code              {state, code} → the code rides this sign-in: redeemed by
 *                                 whichever method finishes it, and with Google or Discord
 *                                 it also signs a newcomer up (codes.ts)
 *   POST /login/password          {state, username, password} → redirect | {next:"totp", ticket}
 *   POST /login/totp              {ticket, code}  (6-digit code or a recovery code)
 *   POST /login/passkey/begin     {state} → WebAuthn request options (discoverable, UV required)
 *   POST /login/passkey/finish    {state, credential}
 *   GET  /account (+ /account/…)  self-service, a built-in audience like the console
 *                                 (POST /account/code redeems an access code there)
 *   GET  /account/setup#code=…    one-time setup link from `hn user add` / `hn user reset`
 *
 * Whatever the method, the result is the same as it always was: a 10-minute,
 * single-use aid1 token delivered to the audience in the URL fragment. The
 * home node keeps no sessions — the account page's credential is its own
 * login token, so "recently authenticated" holds by construction.
 *
 * Ceremony state (login states, TOTP tickets, WebAuthn challenges, pending
 * TOTP secrets, failure counters) is in memory: a restart just means
 * starting the sign-in again.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import type { IssuerKey } from './keys.js';
import { mintToken, newJti, verifyToken, type Aid1Payload } from './token.js';
import { authorizeUrl, botGuildMember, completeOAuth, displayNameOf, oauthScopes, type FetchLike } from './oauth.js';
import { completeGoogle, emailKey, googleAuthorizeUrl, newPkceVerifier, type GoogleIdentity } from './google.js';
import { rejectionText, type AccessCode, type CodeRejection, type CodeStore } from './codes.js';
import {
  anyOpen,
  grantForRoles,
  openSites,
  signupGrant,
  type AudiencesConfig,
  type JsonStore,
  type MintLog,
  type MintRecord,
  type PrincipalStore,
  type RoleGrant,
  type RolesConfig,
} from './stores.js';
import {
  DISCORD_SNAPSHOT_MAX_AGE_MS,
  displayName,
  effectiveRoles,
  withheld,
  hashPassword,
  loginMethods,
  looksLikeRecoveryCode,
  mergeGrants,
  newRecoveryCodes,
  normalizeRecovery,
  normalizeUsername,
  operatorGrant,
  passwordProblem,
  sha256hex,
  usernameProblem,
  verifyPassword,
  type AccountStore,
  type HumanAccount,
} from './accounts.js';
import { newTotpSecret, totpUri, verifyTotp } from './totp.js';
import { qrSvg } from './qr.js';
import { clientDataChallenge, COSE_ALGS, verifyAssertion, verifyRegistration, type RelyingParty } from './webauthn.js';
import { esc, html, json, page, readJson, redirect, securePage } from './http.js';
import { consoleRequiredScopes, type InvitePolicy } from './policy.js';
import { accountPage, loginPage, setupPage } from './pages.js';

const LOGIN_TOKEN_TTL_MS = 10 * 60_000;
const STATE_TTL_MS = 10 * 60_000;
const TICKET_TTL_MS = 5 * 60_000;
const CHALLENGE_TTL_MS = 5 * 60_000;
const TOTP_SETUP_TTL_MS = 15 * 60_000;
const MAX_PENDING = 10_000;

export interface HumanConfig {
  iss: string;
  publicUrl: string;
  discordClientId?: string;
  discordClientSecret?: string;
  discordBotToken?: string;
  googleClientId?: string;
  googleClientSecret?: string;
}

export interface HumanDeps {
  cfg: HumanConfig;
  issuer: IssuerKey;
  accounts: AccountStore;
  codes: CodeStore;
  principals: PrincipalStore;
  roles: JsonStore<RolesConfig>;
  audiences: JsonStore<AudiencesConfig>;
  /** The console's sign-in gate comes from the invite policy (policy.ts). */
  invitePolicy: JsonStore<InvitePolicy>;
  mintLog: MintLog;
  /** Per-IP limiter shared with the other internet-facing routes. */
  allow: (ip: string) => boolean;
  fetchImpl?: FetchLike;
}

/** A link state is bound to the browser that asked for it (`nonce`, also in
 *  an HttpOnly cookie): a link URL handed to someone else can't attach
 *  THEIR Discord or Google to the sender's account. `pkce` is the Google
 *  leg's code verifier, set when that leg starts. */
type LoginState = { audience: string; exp: number; pkce?: string } & (
  /** `code`: an access code entered on the sign-in page, redeemed when the sign-in finishes. */
  | { intent: 'login'; code?: string }
  | { intent: 'link'; provider: 'discord' | 'google'; sub: string; nonce: string }
);
type FactorCheck = 'ok' | 'bad' | 'locked';
const LINK_COOKIE = 'hn_link';
type Who = { sub: string; name: string; grant: RoleGrant | null; account?: HumanAccount; note?: string };
type Outcome = { ok: true; redirect: string } | { ok: false; status: number; error: string };

/** Map with per-entry expiry and a size bound — for ceremony state. */
class Pending<T extends { exp: number }> {
  private m = new Map<string, T>();
  set(k: string, v: T): void {
    const now = Date.now();
    if (this.m.size >= MAX_PENDING) for (const [key, val] of this.m) if (val.exp <= now) this.m.delete(key);
    if (this.m.size >= MAX_PENDING) this.m.delete(this.m.keys().next().value!); // oldest
    this.m.set(k, v);
  }
  get(k: string): T | undefined {
    const v = this.m.get(k);
    if (v && v.exp <= Date.now()) {
      this.m.delete(k);
      return undefined;
    }
    return v;
  }
  take(k: string): T | undefined {
    const v = this.get(k);
    this.m.delete(k);
    return v;
  }
}

/** N failures inside the window locks the key until the window closes. */
class Throttle {
  private m = new Map<string, { n: number; until: number }>();
  constructor(private max: number, private windowMs: number) {}
  locked(k: string, now = Date.now()): boolean {
    const e = this.m.get(k);
    return Boolean(e && e.until > now && e.n >= this.max);
  }
  fail(k: string, now = Date.now()): void {
    const e = this.m.get(k);
    if (!e || e.until <= now) {
      if (this.m.size > MAX_PENDING) this.m.clear();
      this.m.set(k, { n: 1, until: now + this.windowMs });
    } else e.n += 1;
  }
  clear(k: string): void {
    this.m.delete(k);
  }
}

/** The Google link a sign-in writes. `verified` only when Google vouched for
 *  the address it sent just now — an address kept from before (`fallback`)
 *  is not re-vouched. */
function googleLink(g: GoogleIdentity, now: string, fallback = ''): NonNullable<HumanAccount['google']> {
  return {
    sub: g.sub,
    email: g.email ?? fallback,
    ...(g.email && g.emailVerified ? { verified: true } : {}),
    ...(g.name ? { name: g.name } : {}),
    linkedAt: now,
  };
}

export class HumanAuth {
  private states = new Pending<LoginState & { exp: number }>();
  private tickets = new Pending<{ sub: string; state: string; exp: number; tries: number }>();
  private challenges = new Pending<
    | { kind: 'login'; state: string; exp: number }
    | { kind: 'register'; sub: string; userId: string; exp: number }
  >();
  private totpSetups = new Pending<{ secret: string; exp: number }>();
  private pwFailures = new Throttle(5, 15 * 60_000);
  private totpFailures = new Throttle(10, 15 * 60_000);
  readonly rp: RelyingParty;

  constructor(private d: HumanDeps) {
    const u = new URL(d.cfg.publicUrl);
    this.rp = { rpId: u.hostname, origin: u.origin };
  }

  private get discordOn(): boolean {
    return Boolean(this.d.cfg.discordClientId && this.d.cfg.discordClientSecret);
  }
  private get googleOn(): boolean {
    return Boolean(this.d.cfg.googleClientId && this.d.cfg.googleClientSecret);
  }
  private get googleCallbackUrl(): string {
    return `${this.d.cfg.publicUrl}/oauth/google/callback`;
  }

  /** Built-in audiences of this very node — no config entry, no server
   *  session: the login token IS the page's credential. */
  /** For a refusal page: the sites anyone can sign in to, so a newcomer who
   *  started at the wrong door sees where to go. */
  private openHint(except: string): string {
    const sites = openSites(this.d.audiences.get()).filter((o) => o.audience !== except);
    if (!sites.length) return '';
    return `<p>Open to everyone: ${sites.map((o) => `<a href="${esc(o.url)}">${esc(o.host)}</a>`).join(', ')}.</p>`;
  }

  audienceRedirect(audience: string): string | null {
    if (audience === 'console') return `${this.d.cfg.publicUrl}/console`;
    if (audience === 'account') return `${this.d.cfg.publicUrl}/account`;
    return this.d.audiences.get()[audience]?.redirect ?? null;
  }

  /** Handles the route if it's ours; false = not ours. */
  async route(req: IncomingMessage, url: URL, res: ServerResponse, ip: string): Promise<boolean> {
    const p = url.pathname;
    const isLogin = p === '/login' || p.startsWith('/login/') || p === '/oauth/callback' || p === '/oauth/google/callback';
    const isAccount = p === '/account' || p.startsWith('/account/');
    if (!isLogin && !isAccount) return false;
    res.setHeader('cache-control', 'no-store'); // tokens, tickets, challenges: never cached
    if (req.method === 'GET') {
      // The static pages and /account/me are cheap and unlimited (people
      // behind one venue NAT share an address); everything that starts or
      // completes a sign-in is limited.
      if (p === '/account') securePage(res, 200, (n) => accountPage(this.d.cfg.iss, n));
      else if (p === '/account/setup') securePage(res, 200, (n) => setupPage(this.d.cfg.iss, n));
      else if (p === '/account/me') this.me(req, res);
      else if (!isLogin) return false;
      else if (!this.d.allow(ip)) json(res, 429, { error: 'too many requests — wait a minute' });
      else if (p === '/login') this.loginPage(url, res);
      else if (p === '/login/discord') this.discordStart(url, res);
      else if (p === '/oauth/callback') await this.callback(req, url, res);
      else if (p === '/login/google') this.googleStart(url, res);
      else if (p === '/oauth/google/callback') await this.googleCallback(req, url, res);
      else return false;
      return true;
    }
    if (req.method !== 'POST') return false;
    if (!this.d.allow(ip)) {
      json(res, 429, { error: 'too many requests — wait a minute' });
      return true;
    }
    // JSON only: a cross-site <form> can't send it without a CORS preflight,
    // which this node never grants — the login-CSRF guard for these POSTs.
    if (!/^application\/json\b/.test(req.headers['content-type'] ?? '')) {
      json(res, 415, { error: 'expected application/json' });
      return true;
    }
    const body = ((await readJson(req)) ?? {}) as Record<string, unknown>;
    const h = this.posts[p];
    if (!h) return false;
    await h(req, res, body);
    return true;
  }

  private posts: Record<string, (req: IncomingMessage, res: ServerResponse, b: Record<string, unknown>) => Promise<void> | void> = {
    '/login/code': (_q, res, b) => this.loginCode(res, b),
    '/login/password': (_q, res, b) => this.loginPassword(res, b),
    '/login/totp': (_q, res, b) => this.loginTotp(res, b),
    '/login/passkey/begin': (_q, res, b) => this.passkeyLoginBegin(res, b),
    '/login/passkey/finish': (_q, res, b) => this.passkeyLoginFinish(res, b),
    '/account/setup/info': (_q, res, b) => this.setupInfo(res, b),
    '/account/setup': (_q, res, b) => this.setupFinish(res, b),
    '/account/password': (q, res, b) => this.withAccount(q, res, (t) => this.setPassword(res, t, b)),
    '/account/totp/begin': (q, res) => this.withAccount(q, res, (t) => this.totpBegin(res, t)),
    '/account/totp/confirm': (q, res, b) => this.withAccount(q, res, (t) => this.totpConfirm(res, t, b)),
    '/account/totp/disable': (q, res, b) => this.withAccount(q, res, (t) => this.totpDisable(res, t, b)),
    '/account/recovery': (q, res, b) => this.withAccount(q, res, (t) => this.recoveryRegenerate(res, t, b)),
    '/account/passkeys/begin': (q, res) => this.withAccount(q, res, (t) => this.passkeyAddBegin(res, t)),
    '/account/passkeys/finish': (q, res, b) => this.withAccount(q, res, (t) => this.passkeyAddFinish(res, t, b)),
    '/account/passkeys/remove': (q, res, b) => this.withAccount(q, res, (t) => this.passkeyRemove(res, t, b)),
    '/account/discord/link': (q, res) => this.withAccount(q, res, (t) => this.discordLink(res, t)),
    '/account/discord/unlink': (q, res) => this.withAccount(q, res, (t) => this.discordUnlink(res, t)),
    '/account/code': (q, res, b) => this.withAccount(q, res, (t) => this.accountCode(res, t, b)),
    '/account/google/link': (q, res) => this.withAccount(q, res, (t) => this.googleLink(res, t)),
    '/account/google/unlink': (q, res) => this.withAccount(q, res, (t) => this.googleUnlink(res, t)),
  };

  // ── sign-in ──

  private newState(s: LoginState): string {
    const state = randomBytes(24).toString('base64url');
    this.states.set(state, s);
    return state;
  }

  private loginPage(url: URL, res: ServerResponse): void {
    const audience = url.searchParams.get('audience') ?? '';
    if (!this.audienceRedirect(audience)) {
      return html(res, 400, page('unknown audience', `<p>Unknown audience <code>${esc(audience)}</code>.</p>`));
    }
    const state = this.newState({ intent: 'login', audience, exp: Date.now() + STATE_TTL_MS });
    if (url.searchParams.get('via') === 'discord' && this.discordOn) return this.toDiscord(res, state);
    if (url.searchParams.get('via') === 'google' && this.googleOn) return this.toGoogle(res, state);
    securePage(res, 200, (nonce) =>
      loginPage({ iss: this.d.cfg.iss, audience, state, discord: this.discordOn, google: this.googleOn, open: !!signupGrant(this.d.audiences.get()[audience]), nonce }),
    );
  }

  private discordStart(url: URL, res: ServerResponse): void {
    const state = url.searchParams.get('state') ?? '';
    if (!this.states.get(state)) {
      return html(res, 400, page('login expired', '<p>Login attempt expired or invalid — start again from the service.</p>'));
    }
    if (!this.discordOn) return html(res, 503, page('login unavailable', '<p>Discord login is not configured on this node.</p>'));
    this.toDiscord(res, state);
  }

  private toDiscord(res: ServerResponse, state: string): void {
    redirect(
      res,
      authorizeUrl(this.d.cfg.discordClientId!, `${this.d.cfg.publicUrl}/oauth/callback`, state, oauthScopes(Boolean(this.d.cfg.discordBotToken))),
    );
  }

  private async callback(req: IncomingMessage, url: URL, res: ServerResponse): Promise<void> {
    const state = url.searchParams.get('state') ?? '';
    const code = url.searchParams.get('code') ?? '';
    const st = this.states.take(state); // single-use, success or not
    if (!st) {
      return html(res, 400, page('login expired', '<p>Login attempt expired or invalid — start again from the service.</p>'));
    }
    if (st.intent === 'link') {
      res.setHeader('set-cookie', this.linkCookie('', 0, '/oauth/callback')); // spent either way
      if (st.provider !== 'discord' || !safeEqual(cookie(req, LINK_COOKIE), st.nonce)) {
        console.error(`[hn] link refused for ${st.sub}: finished in a browser that didn't start it`);
        return html(res, 403, page('link refused', '<p>Linking Discord has to finish in the same browser that started it. Start again from your <a href="/login?audience=account">sign-in settings</a>.</p>'));
      }
    }
    if (!code || !this.discordOn) {
      return html(res, 400, page('login failed', '<p>Discord did not complete the login.</p>'));
    }
    const { user, member } = await completeOAuth(
      {
        clientId: this.d.cfg.discordClientId!,
        clientSecret: this.d.cfg.discordClientSecret!,
        redirectUri: `${this.d.cfg.publicUrl}/oauth/callback`,
        code,
        guildId: this.d.roles.get().guildId,
        botToken: this.d.cfg.discordBotToken,
      },
      this.d.fetchImpl,
    );
    const discordName = displayNameOf(user, member);
    // Roles the operator set aside for this person don't count (accounts.ts).
    const target = st.intent === 'link' ? this.d.accounts.bySub(st.sub) : this.d.accounts.byDiscord(user.id);
    const discordGrant = member ? grantForRoles(effectiveRoles(member.roles, target), this.d.roles.get()) : null;
    const snapshot = { id: user.id, name: discordName, grant: discordGrant, checkedAt: new Date().toISOString() };

    if (st.intent === 'link') {
      const other = this.d.accounts.byDiscord(user.id);
      if (other && other.sub !== st.sub) {
        return html(res, 409, page('already linked', `<p>That Discord account (<b>${esc(discordName)}</b>) is already linked to another account here.</p>`));
      }
      let acct: HumanAccount | undefined;
      try {
        acct = this.d.accounts.update(st.sub, (a) => {
          if (a.disabled || a.discord) throw new Error('account changed');
          return { ...a, discord: snapshot };
        });
      } catch {
        acct = undefined;
      }
      if (!acct) return html(res, 400, page('link failed', '<p>That account can’t take a Discord link right now. Start again from your sign-in settings.</p>'));
      console.error(`[hn] account: ${acct.sub} linked discord:${user.id} (${discordName})`);
      const out = this.issue('account', { sub: acct.sub, name: displayName(acct), grant: this.storedGrant(acct), account: acct }, 'oauth');
      return out.ok ? redirect(res, out.redirect) : html(res, out.status, page('no access', `<p>${esc(out.error)}</p>`));
    }

    let acct = this.d.accounts.byDiscord(user.id);
    if (acct) acct = this.d.accounts.update(acct.sub, (a) => ({ ...a, discord: snapshot }));
    if (acct?.disabled) {
      console.error(`[hn] login refused: ${acct.sub} via discord — account disabled`);
      return html(res, 403, page('account disabled', '<p>This account is disabled. Ask an operator.</p>'));
    }
    if (st.code) {
      // A code rides this sign-in: redeemed into the row, made now if this
      // Discord person had none.
      const r = acct
        ? this.redeemInto(acct.sub, st.code)
        : this.signUp(`human:discord:${user.id}`, st.code, { discord: snapshot });
      if (typeof r === 'string') return html(res, 403, page('code not accepted', `<p>${esc(cap(rejectionText(r)))}. Sign in without it, or ask for a new code.</p>`));
      acct = r.account;
    }
    const grant = mergeGrants(discordGrant, operatorGrant(acct));
    const who: Who = acct
      ? { sub: acct.sub, name: displayName(acct), grant, account: acct }
      : { sub: `human:discord:${user.id}`, name: discordName, grant };
    const out = this.issue(st.audience, who, 'oauth');
    if (out.ok) return redirect(res, out.redirect);
    console.error(`[hn] login refused: discord:${user.id} (${user.username}) at ${st.audience} — ${out.error}`);
    return html(res, out.status, page('no access', `<p>Hi <b>${esc(who.name)}</b> — your Discord account
doesn't have a role that grants access to <b>${esc(st.audience)}</b>${member ? '' : ' (you are not in the guild)'}. If you were given an access code, enter it on the sign-in page; otherwise ask an operator for access.</p>${this.openHint(st.audience)}`));
  }

  private async loginPassword(res: ServerResponse, b: Record<string, unknown>): Promise<void> {
    const st = this.states.get(String(b.state ?? ''));
    if (!st || st.intent !== 'login') return json(res, 400, { error: 'this sign-in page expired — reload it' });
    const username = normalizeUsername(String(b.username ?? ''));
    const password = String(b.password ?? '');
    if (!username || !password) return json(res, 400, { error: 'username and password required' });
    if (this.pwFailures.locked(username)) {
      return json(res, 429, { error: 'too many failed attempts for this username — try again in 15 minutes, or use a passkey' });
    }
    const acct = this.d.accounts.byUsername(username);
    const ok = await verifyPassword(password, acct?.password); // constant-ish time either way
    if (!acct || !ok || acct.disabled) {
      this.pwFailures.fail(username);
      if (acct?.disabled && ok) return json(res, 403, { error: 'this account is disabled' });
      return json(res, 401, { error: 'wrong username or password' });
    }
    this.pwFailures.clear(username);
    if (acct.totp) {
      const ticket = randomBytes(24).toString('base64url');
      this.tickets.set(ticket, { sub: acct.sub, state: String(b.state), exp: Date.now() + TICKET_TTL_MS, tries: 0 });
      return json(res, 200, { next: 'totp', ticket });
    }
    return this.respond(res, await this.finishLogin(String(b.state), acct, 'password'));
  }

  private async loginTotp(res: ServerResponse, b: Record<string, unknown>): Promise<void> {
    const ticketId = String(b.ticket ?? '');
    const t = this.tickets.get(ticketId);
    if (!t) return json(res, 400, { error: 'that step expired — sign in again' });
    const acct = this.d.accounts.bySub(t.sub);
    if (!acct?.totp) return json(res, 400, { error: 'that step expired — sign in again' });
    if (acct.disabled) {
      this.tickets.take(ticketId);
      return json(res, 403, { error: 'this account is disabled' });
    }
    const check = this.checkSecondFactor(acct, String(b.code ?? ''));
    if (check === 'locked') {
      this.tickets.take(ticketId);
      return json(res, 429, { error: 'too many wrong codes — wait 15 minutes, or use a passkey' });
    }
    if (check === 'bad') {
      t.tries += 1;
      if (t.tries >= 5) {
        this.tickets.take(ticketId);
        return json(res, 401, { error: 'wrong code — too many tries, sign in again', restart: true });
      }
      return json(res, 401, { error: 'wrong code' });
    }
    this.tickets.take(ticketId);
    return this.respond(res, await this.finishLogin(t.state, this.d.accounts.bySub(acct.sub)!, 'password'));
  }

  /**
   * A current TOTP code (each usable once) or an unused recovery code —
   * EVERY second-factor check goes through here, so the per-account lockout
   * (10 wrong codes / 15 min) covers sign-in, setup links, turning 2FA off
   * and new recovery codes alike. Consumes what it accepts.
   */
  private checkSecondFactor(acct: HumanAccount, code: string, opts: { recovery?: boolean } = {}): FactorCheck {
    if (!acct.totp) return 'bad';
    if (this.totpFailures.locked(acct.sub)) return 'locked';
    const ok = looksLikeRecoveryCode(code) ? opts.recovery !== false && this.useRecoveryCode(acct, code) : this.useTotp(acct, code);
    if (!ok) {
      this.totpFailures.fail(acct.sub);
      return 'bad';
    }
    this.totpFailures.clear(acct.sub);
    return 'ok';
  }

  private useRecoveryCode(acct: HumanAccount, code: string): boolean {
    const h = sha256hex(normalizeRecovery(code));
    if (!acct.recovery?.includes(h)) return false; // wrong: no lock, no write
    let left = -1;
    this.d.accounts.update(acct.sub, (a) => {
      if (!a.recovery?.includes(h)) return a;
      const recovery = a.recovery.filter((x) => x !== h);
      left = recovery.length;
      return { ...a, recovery };
    });
    if (left < 0) return false;
    console.error(`[hn] account: ${acct.sub} used a recovery code (${left} left)`);
    return true;
  }

  private useTotp(acct: HumanAccount, code: string): boolean {
    // Wrong or replayed against the row we hold: no lock, no write. Right:
    // re-checked under the lock against the stored lastStep, then recorded.
    if (!acct.totp || verifyTotp(acct.totp.secret, code, { lastStep: acct.totp.lastStep }) === null) return false;
    let ok = false;
    this.d.accounts.update(acct.sub, (a) => {
      // against the stored lastStep as it is now: a code is good once
      const step = a.totp ? verifyTotp(a.totp.secret, code, { lastStep: a.totp.lastStep }) : null;
      if (step === null || !a.totp) return a;
      ok = true;
      return { ...a, totp: { ...a.totp, lastStep: step } };
    });
    return ok;
  }

  private passkeyLoginBegin(res: ServerResponse, b: Record<string, unknown>): void {
    const state = String(b.state ?? '');
    const st = this.states.get(state);
    if (!st || st.intent !== 'login') return json(res, 400, { error: 'this sign-in page expired — reload it' });
    const challenge = randomBytes(32).toString('base64url');
    this.challenges.set(challenge, { kind: 'login', state, exp: Date.now() + CHALLENGE_TTL_MS });
    json(res, 200, {
      publicKey: { challenge, rpId: this.rp.rpId, userVerification: 'required', timeout: CHALLENGE_TTL_MS, allowCredentials: [] },
    });
  }

  private async passkeyLoginFinish(res: ServerResponse, b: Record<string, unknown>): Promise<void> {
    const cred = (b.credential ?? {}) as { id?: unknown; response?: Record<string, unknown> };
    const challenge = clientDataChallenge(cred.response?.clientDataJSON) ?? '';
    const ch = this.challenges.take(challenge);
    if (!ch || ch.kind !== 'login' || ch.state !== b.state) return json(res, 400, { error: 'passkey sign-in expired — try again' });
    const found = typeof cred.id === 'string' ? this.d.accounts.byPasskey(cred.id) : undefined;
    if (!found) return json(res, 401, { error: 'this passkey isn’t registered here (it may have been removed)' });
    const { account, passkey } = found;
    const handle = cred.response?.userHandle;
    if (typeof handle === 'string' && handle && account.webauthnUserId && handle !== account.webauthnUserId) {
      return json(res, 401, { error: 'passkey does not belong to this account' });
    }
    const v = verifyAssertion(cred, challenge, this.rp, passkey);
    if (!v.ok) {
      console.error(`[hn] passkey login refused for ${account.sub}: ${v.reason}`);
      return json(res, 401, { error: `passkey check failed: ${v.reason}` });
    }
    if (account.disabled) return json(res, 403, { error: 'this account is disabled' });
    const now = new Date().toISOString();
    const fresh = this.d.accounts.update(account.sub, (a) => ({
      ...a,
      passkeys: (a.passkeys ?? []).map((p) => (p.id === passkey.id ? { ...p, signCount: v.signCount, lastUsedAt: now } : p)),
    }))!;
    return this.respond(res, await this.finishLogin(String(b.state), fresh, 'passkey'));
  }

  /** Password/passkey path: resolve the grant (Discord leg included), mint,
   *  and consume the login state. */
  private async finishLogin(state: string, acct: HumanAccount, by: MintRecord['by']): Promise<Outcome> {
    const st = this.states.get(state);
    if (!st || st.intent !== 'login') return { ok: false, status: 400, error: 'this sign-in page expired — reload it' };
    let live = this.d.accounts.bySub(acct.sub);
    if (!live || live.disabled) return { ok: false, status: 403, error: 'this account is disabled' };
    if (st.code) {
      const r = this.redeemInto(live.sub, st.code);
      if (typeof r === 'string') return { ok: false, status: 400, error: rejectionText(r) };
      live = r.account;
    }
    const who = await this.resolve(live);
    if (this.d.accounts.bySub(acct.sub)?.disabled) return { ok: false, status: 403, error: 'this account is disabled' };
    const out = this.issue(st.audience, who, by);
    if (out.ok) this.states.take(state);
    else console.error(`[hn] login refused: ${acct.sub} via ${by} — ${out.error}`);
    return out;
  }

  /**
   * What a Discord-linked account holds when it signs in some other way:
   * roles read live by bot token when configured; otherwise (or if Discord
   * is unreachable) the snapshot from its last Discord check, if recent.
   */
  private async resolve(acct: HumanAccount): Promise<Who> {
    let discordGrant: RoleGrant | null = null;
    let note: string | undefined;
    let account = acct;
    const dc = acct.discord;
    if (dc) {
      let live = false;
      if (this.d.cfg.discordBotToken && this.d.roles.get().guildId) {
        try {
          const m = await botGuildMember(this.d.cfg.discordBotToken, this.d.roles.get().guildId, dc.id, this.d.fetchImpl);
          discordGrant = m ? grantForRoles(effectiveRoles(m.roles, acct), this.d.roles.get()) : null;
          const name = m?.user ? displayNameOf(m.user, m) : dc.name;
          account =
            this.d.accounts.update(acct.sub, (a) => ({
              ...a,
              discord: { ...dc, name, grant: discordGrant, checkedAt: new Date().toISOString() },
            })) ?? acct;
          live = true;
        } catch (err) {
          console.error(`[hn] discord role re-check failed for ${acct.sub}: ${(err as Error).message} — using snapshot`);
        }
      }
      if (!live) {
        const age = dc.checkedAt ? Date.now() - Date.parse(dc.checkedAt) : Infinity;
        if (age <= DISCORD_SNAPSHOT_MAX_AGE_MS) discordGrant = dc.grant ?? null;
        else note = 'your Discord roles need re-checking — sign in with Discord once, then this works again';
      }
    }
    return { sub: account.sub, name: displayName(account), grant: mergeGrants(discordGrant, operatorGrant(account)), account, note };
  }

  /** Grant without any network: for the account page after a link. */
  private storedGrant(acct: HumanAccount): RoleGrant | null {
    return mergeGrants(acct.discord?.grant, operatorGrant(acct));
  }

  /** Policy + mint, shared by every method. */
  private issue(audience: string, who: Who, by: MintRecord['by']): Outcome {
    const target = this.audienceRedirect(audience);
    if (!target) return { ok: false, status: 400, error: `unknown audience ${audience}` };
    // Codes count for their own audiences only (codes.ts) — read live, so a
    // revoked code stops working at the next sign-in.
    const live = this.d.accounts.bySub(who.sub);
    // Codes, and an audience open to newcomers, count for that audience only.
    const grant = withheld(mergeGrants(who.grant, this.d.codes.grantFor(live?.codes, audience), signupGrant(this.d.audiences.get()[audience])), live);
    if (audience === 'account') {
      // Managing your own sign-in needs an account, or a Discord login that
      // would qualify for something (strangers don't get to create rows).
      if (!who.account && !grant) return { ok: false, status: 403, error: 'no qualifying role' };
    } else {
      const gate = audience === 'console' ? consoleRequiredScopes(this.d.invitePolicy.get()) : null;
      if (audience === 'console' && gate === null) {
        return { ok: false, status: 403, error: 'this home has no sponsor console (no config/invite-policy.json)' };
      }
      const needed = audience === 'console' ? gate! : (this.d.audiences.get()[audience]?.requiredScopes ?? []);
      if (!grant) return { ok: false, status: 403, error: who.note ?? 'no qualifying role' };
      const missing = needed.filter((s) => !grant.scopes.includes(s));
      if (missing.length) {
        return { ok: false, status: 403, error: who.note ?? `missing ${missing.join(', ')} for ${audience}` };
      }
    }
    const nowMs = Date.now();
    const payload: Aid1Payload = {
      v: 1,
      iss: this.d.cfg.iss,
      sub: who.sub,
      kind: 'human',
      name: who.name,
      aud: audience,
      scopes: grant?.scopes ?? [],
      ...(grant?.claims ? { claims: grant.claims } : {}),
      iat: Math.floor(nowMs / 1000),
      exp: Math.floor((nowMs + LOGIN_TOKEN_TTL_MS) / 1000),
      jti: newJti(),
    };
    const token = mintToken(this.d.issuer.privateKey, payload);
    this.d.mintLog.append({
      at: new Date(nowMs).toISOString(), jti: payload.jti, sub: payload.sub, aud: payload.aud, scopes: payload.scopes, exp: payload.exp, by,
    });
    console.error(`[hn] login (${by}): ${payload.sub} (${payload.name}) → ${payload.aud} [${payload.scopes.join(' ')}]`);
    // Token rides the fragment — never hits logs or Referer headers (§8).
    return { ok: true, redirect: `${target}#token=${token}` };
  }

  private respond(res: ServerResponse, out: Outcome): void {
    if (out.ok) json(res, 200, { redirect: out.redirect });
    else json(res, out.status, { error: out.status === 403 && !/disabled/.test(out.error) ? `signed in, but no access: ${out.error}` : out.error });
  }

  // ── account page API (Bearer = an aud:"account" login token; 401 here
  //    always means that token is bad/expired — wrong codes/passwords are 400) ──

  private accountToken(req: IncomingMessage, res: ServerResponse): Aid1Payload | null {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization ?? '');
    const v = m
      ? verifyToken(m[1]!, { issuerId: this.d.issuer.id, iss: this.d.cfg.iss, aud: 'account' })
      : ({ ok: false, reason: 'no bearer token' } as const);
    if (!v.ok || v.payload.kind !== 'human') {
      json(res, 401, { error: v.ok ? 'not a person' : v.reason });
      return null;
    }
    if (this.d.accounts.bySub(v.payload.sub)?.disabled) {
      json(res, 403, { error: 'account disabled' });
      return null;
    }
    return v.payload;
  }

  private async withAccount(req: IncomingMessage, res: ServerResponse, fn: (t: Aid1Payload) => Promise<void> | void): Promise<void> {
    const t = this.accountToken(req, res);
    if (t) await fn(t);
  }

  /** The row for this token, creating it for a Discord-only person on their
   *  first change (their sub stays `human:discord:<id>`). */
  private ensureAccount(t: Aid1Payload): HumanAccount | null {
    const existing = this.d.accounts.bySub(t.sub);
    if (existing) return existing;
    const m = /^human:discord:(\d+)$/.exec(t.sub);
    if (!m || this.d.accounts.byDiscord(m[1]!)) return null; // linked to another row since this token was minted
    try {
      return this.d.accounts.add({
      sub: t.sub,
      discord: {
        id: m[1]!,
        name: t.name,
        grant: t.scopes.length ? { scopes: t.scopes, ...(t.claims ? { claims: t.claims } : {}) } : null,
          checkedAt: new Date(t.iat * 1000).toISOString(),
        },
        createdAt: new Date().toISOString(),
      });
    } catch {
      return this.d.accounts.bySub(t.sub) ?? null; // another tab made it a moment ago
    }
  }

  private view(t: Aid1Payload): Record<string, unknown> {
    const a = this.d.accounts.bySub(t.sub);
    const discordAnchored = t.sub.startsWith('human:discord:');
    return {
      sub: t.sub,
      name: a ? displayName(a) : t.name,
      exp: t.exp,
      username: a?.username ?? null,
      hasPassword: Boolean(a?.password),
      totp: a?.totp ? { since: a.totp.enabledAt, recoveryLeft: a.recovery?.length ?? 0 } : null,
      passkeys: (a?.passkeys ?? []).map((p) => ({ id: p.id, name: p.name, createdAt: p.createdAt, lastUsedAt: p.lastUsedAt ?? null })),
      discord: a?.discord
        ? { id: a.discord.id, name: a.discord.name ?? null, canUnlink: !discordAnchored }
        : discordAnchored
          ? { id: t.sub.slice('human:discord:'.length), name: t.name, canUnlink: false }
          : null,
      canLinkDiscord: this.discordOn && !discordAnchored && !a?.discord,
      google: a?.google ? { email: a.google.email, linked: Boolean(a.google.sub) } : null,
      canLinkGoogle: this.googleOn && !a?.google?.sub,
      codes: (a?.codes ?? []).flatMap((r) => {
        const c = this.d.codes.byId(r.id);
        return c && !c.revoked ? [{ label: c.label, audiences: c.audiences, at: r.at }] : [];
      }),
      scopes: t.scopes,
      open: openSites(this.d.audiences.get()).map((o) => ({ url: o.url, host: o.host })),
    };
  }

  private me(req: IncomingMessage, res: ServerResponse): void {
    const t = this.accountToken(req, res);
    if (t) json(res, 200, this.view(t));
  }

  private async setPassword(res: ServerResponse, t: Aid1Payload, b: Record<string, unknown>): Promise<void> {
    const cur = this.d.accounts.bySub(t.sub);
    if (cur?.password) {
      if (!(await verifyPassword(String(b.current ?? ''), cur.password))) {
        return json(res, 400, { error: 'current password is wrong' });
      }
    }
    let username = cur?.username;
    if (!username) {
      const want = normalizeUsername(String(b.username ?? ''));
      const bad = usernameProblem(want, this.d.accounts, (n) => this.d.principals.nameTaken(n), t.sub);
      if (bad) return json(res, 400, { error: bad });
      username = want;
    }
    const pwBad = passwordProblem(b.password, username);
    if (pwBad) return json(res, 400, { error: pwBad });
    const hash = await hashPassword(String(b.password));
    const acct = this.ensureAccount(t);
    if (!acct) return json(res, 404, { error: 'no account' });
    // Re-check the name under the write: two tabs racing for one username.
    if (!acct.username && usernameProblem(username, this.d.accounts, (n) => this.d.principals.nameTaken(n), acct.sub)) {
      return json(res, 409, { error: 'that username was just taken' });
    }
    try {
      this.d.accounts.update(acct.sub, (a) => ({ ...a, username: a.username ?? username, password: hash }));
    } catch (err) {
      return json(res, 409, { error: (err as Error).message });
    }
    console.error(`[hn] account: ${acct.sub} ${cur?.password ? 'changed' : 'set'} password (username ${username})`);
    json(res, 200, this.view(t));
  }

  private totpBegin(res: ServerResponse, t: Aid1Payload): void {
    const a = this.d.accounts.bySub(t.sub);
    if (!a?.password) return json(res, 400, { error: 'set a password first — the code protects password sign-in' });
    if (a.totp) return json(res, 400, { error: 'two-factor is already on' });
    const secret = newTotpSecret();
    this.totpSetups.set(t.sub, { secret, exp: Date.now() + TOTP_SETUP_TTL_MS });
    const uri = totpUri(secret, a.username ?? displayName(a), this.d.cfg.iss);
    json(res, 200, { secret, uri, qr: qrSvg(uri) });
  }

  private totpConfirm(res: ServerResponse, t: Aid1Payload, b: Record<string, unknown>): void {
    const pending = this.totpSetups.get(t.sub);
    if (!pending) return json(res, 400, { error: 'setup expired — start again' });
    const step = verifyTotp(pending.secret, String(b.code ?? ''));
    if (step === null) return json(res, 400, { error: 'that code doesn’t match — check the clock on your phone and try the next one' });
    this.totpSetups.take(t.sub);
    const { codes, hashes } = newRecoveryCodes();
    this.d.accounts.update(t.sub, (a) => ({
      ...a,
      totp: { secret: pending.secret, lastStep: step, enabledAt: new Date().toISOString() },
      recovery: hashes,
    }));
    console.error(`[hn] account: ${t.sub} turned on two-factor`);
    json(res, 200, { ...this.view(t), recoveryCodes: codes });
  }

  private totpDisable(res: ServerResponse, t: Aid1Payload, b: Record<string, unknown>): void {
    const a = this.d.accounts.bySub(t.sub);
    if (!a?.totp) return json(res, 400, { error: 'two-factor is not on' });
    const check = this.checkSecondFactor(a, String(b.code ?? ''));
    if (check === 'locked') return json(res, 429, { error: 'too many wrong codes — wait 15 minutes' });
    if (check === 'bad') return json(res, 400, { error: 'wrong code' });
    this.d.accounts.update(t.sub, (x) => {
      const { totp: _t, recovery: _r, ...rest } = x;
      return rest;
    });
    console.error(`[hn] account: ${t.sub} turned off two-factor`);
    json(res, 200, this.view(t));
  }

  private recoveryRegenerate(res: ServerResponse, t: Aid1Payload, b: Record<string, unknown>): void {
    const a = this.d.accounts.bySub(t.sub);
    if (!a?.totp) return json(res, 400, { error: 'two-factor is not on' });
    const check = this.checkSecondFactor(a, String(b.code ?? ''), { recovery: false });
    if (check === 'locked') return json(res, 429, { error: 'too many wrong codes — wait 15 minutes' });
    if (check === 'bad') return json(res, 400, { error: 'enter a current code from your authenticator app' });
    const { codes, hashes } = newRecoveryCodes();
    this.d.accounts.update(t.sub, (x) => ({ ...x, recovery: hashes }));
    json(res, 200, { ...this.view(t), recoveryCodes: codes });
  }

  private passkeyAddBegin(res: ServerResponse, t: Aid1Payload): void {
    let a = this.d.accounts.bySub(t.sub);
    if ((a?.passkeys?.length ?? 0) >= 20) return json(res, 400, { error: 'that’s plenty of passkeys — remove one first' });
    // The WebAuthn user handle is saved BEFORE any options go out, so two
    // tabs registering at once both use the one stored handle.
    if (!a?.webauthnUserId) {
      const row = this.ensureAccount(t);
      if (!row) return json(res, 404, { error: 'no account' });
      a = this.d.accounts.update(row.sub, (x) => (x.webauthnUserId ? x : { ...x, webauthnUserId: randomBytes(16).toString('base64url') }));
    }
    const userId = a!.webauthnUserId!;
    const challenge = randomBytes(32).toString('base64url');
    this.challenges.set(challenge, { kind: 'register', sub: t.sub, userId, exp: Date.now() + CHALLENGE_TTL_MS });
    const label = a?.username ?? (a ? displayName(a) : t.name);
    json(res, 200, {
      publicKey: {
        challenge,
        rp: { id: this.rp.rpId, name: this.d.cfg.iss },
        user: { id: userId, name: label, displayName: a ? displayName(a) : t.name },
        pubKeyCredParams: COSE_ALGS.map((alg) => ({ type: 'public-key', alg })),
        timeout: CHALLENGE_TTL_MS,
        attestation: 'none',
        authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
        excludeCredentials: (a?.passkeys ?? []).map((p) => ({ type: 'public-key', id: p.id })),
      },
    });
  }

  private passkeyAddFinish(res: ServerResponse, t: Aid1Payload, b: Record<string, unknown>): void {
    const cred = (b.credential ?? {}) as { id?: unknown; response?: Record<string, unknown> };
    const challenge = clientDataChallenge(cred.response?.clientDataJSON) ?? '';
    const ch = this.challenges.take(challenge);
    if (!ch || ch.kind !== 'register' || ch.sub !== t.sub) return json(res, 400, { error: 'passkey setup expired — try again' });
    const v = verifyRegistration(cred, challenge, this.rp);
    if (!v.ok) return json(res, 400, { error: `passkey not accepted: ${v.reason}` });
    if (this.d.accounts.byPasskey(v.credentialId)) return json(res, 409, { error: 'that passkey is already registered' });
    const acct = this.d.accounts.bySub(t.sub);
    if (!acct || acct.webauthnUserId !== ch.userId) return json(res, 400, { error: 'passkey setup expired — try again' });
    const name = String(b.name ?? '').trim().slice(0, 40) || `passkey ${(acct.passkeys?.length ?? 0) + 1}`;
    const now = new Date().toISOString();
    try {
      this.d.accounts.update(acct.sub, (a) => ({
        ...a,
        passkeys: [...(a.passkeys ?? []), { id: v.credentialId, jwk: v.jwk, alg: v.alg, signCount: v.signCount, name, createdAt: now }],
      }));
    } catch (err) {
      return json(res, 409, { error: (err as Error).message });
    }
    console.error(`[hn] account: ${acct.sub} added passkey "${name}" (alg ${v.alg})`);
    json(res, 200, this.view(t));
  }

  private passkeyRemove(res: ServerResponse, t: Aid1Payload, b: Record<string, unknown>): void {
    const a = this.d.accounts.bySub(t.sub);
    const id = String(b.id ?? '');
    if (!a?.passkeys?.some((p) => p.id === id)) return json(res, 404, { error: 'no such passkey' });
    if (loginMethods(a) <= 1) return json(res, 400, { error: 'that’s your only way to sign in — add another first' });
    this.d.accounts.update(t.sub, (x) => ({ ...x, passkeys: (x.passkeys ?? []).filter((p) => p.id !== id) }));
    console.error(`[hn] account: ${t.sub} removed a passkey`);
    json(res, 200, this.view(t));
  }

  private discordLink(res: ServerResponse, t: Aid1Payload): void {
    const a = this.d.accounts.bySub(t.sub);
    if (!this.discordOn) return json(res, 400, { error: 'Discord login is not configured on this node' });
    if (!a || t.sub.startsWith('human:discord:') || a.discord) return json(res, 400, { error: 'nothing to link' });
    const nonce = randomBytes(24).toString('base64url');
    const state = this.newState({ intent: 'link', provider: 'discord', sub: t.sub, nonce, audience: 'account', exp: Date.now() + STATE_TTL_MS });
    res.setHeader('set-cookie', this.linkCookie(nonce, STATE_TTL_MS / 1000, '/oauth/callback'));
    json(res, 200, { url: `${this.d.cfg.publicUrl}/login/discord?state=${state}` });
  }

  /** HttpOnly, scoped to that provider's callback; Lax so the provider's
   *  redirect back (a top-level GET) carries it. */
  private linkCookie(value: string, maxAgeS: number, path: '/oauth/callback' | '/oauth/google/callback'): string {
    const secure = this.d.cfg.publicUrl.startsWith('https:') ? '; Secure' : '';
    return `${LINK_COOKIE}=${value}; Path=${path}; Max-Age=${maxAgeS}; HttpOnly; SameSite=Lax${secure}`;
  }

  private discordUnlink(res: ServerResponse, t: Aid1Payload): void {
    const a = this.d.accounts.bySub(t.sub);
    if (!a?.discord) return json(res, 400, { error: 'no Discord account linked' });
    if (t.sub.startsWith('human:discord:')) {
      return json(res, 400, { error: 'this account IS your Discord identity — it can’t be unlinked' });
    }
    if (loginMethods(a) <= 1) return json(res, 400, { error: 'that’s your only way to sign in — add another first' });
    this.d.accounts.update(t.sub, (x) => {
      const { discord: _d, ...rest } = x;
      return rest;
    });
    console.error(`[hn] account: ${t.sub} unlinked discord:${a.discord.id}`);
    json(res, 200, this.view(t));
  }

  // ── access codes ──

  private loginCode(res: ServerResponse, b: Record<string, unknown>): void {
    const st = this.states.get(String(b.state ?? ''));
    if (!st || st.intent !== 'login') return json(res, 400, { error: 'this sign-in page expired — reload it' });
    const c = this.d.codes.check(String(b.code ?? ''));
    if (typeof c === 'string') return json(res, 400, { error: rejectionText(c) });
    st.code = String(b.code);
    json(res, 200, { label: c.label, audiences: c.audiences });
  }

  private accountCode(res: ServerResponse, t: Aid1Payload, b: Record<string, unknown>): void {
    const a = this.ensureAccount(t);
    if (!a) return json(res, 404, { error: 'no account' });
    const r = this.redeemInto(a.sub, String(b.code ?? ''));
    if (typeof r === 'string') return json(res, 400, { error: rejectionText(r) });
    json(res, 200, { ...this.view(t), redeemed: { label: r.code.label, audiences: r.code.audiences } });
  }

  /** Redeem a code into an existing row. */
  private redeemInto(sub: string, code: string): { code: AccessCode; account: HumanAccount } | CodeRejection {
    const c = this.d.codes.redeem(code, sub);
    if (typeof c === 'string') return c;
    const at = new Date().toISOString();
    const had = Boolean(this.d.accounts.bySub(sub)?.codes?.some((x) => x.id === c.id));
    const account = this.d.accounts.update(sub, (a) => (a.codes?.some((x) => x.id === c.id) ? a : { ...a, codes: [...(a.codes ?? []), { id: c.id, at }] }));
    if (!account) return 'unknown';
    if (!had) console.error(`[hn] account: ${sub} redeemed ${c.id} (${c.label}) → ${c.audiences.join(', ')}`);
    return { code: c, account };
  }

  /** A newcomer with a code: the code is spent first, then their row is made. */
  private signUp(sub: string, code: string, anchor: Pick<HumanAccount, 'discord' | 'google'>): { code: AccessCode; account: HumanAccount } | CodeRejection {
    const existing = this.d.accounts.bySub(sub);
    if (existing) return this.redeemInto(sub, code);
    const c = this.d.codes.redeem(code, sub);
    if (typeof c === 'string') return c;
    const at = new Date().toISOString();
    let account: HumanAccount;
    try {
      account = this.d.accounts.add({ sub, ...anchor, codes: [{ id: c.id, at }], createdAt: at, notes: `signed up with ${c.id}` });
    } catch {
      return this.redeemInto(sub, code); // another tab made it a moment ago
    }
    console.error(`[hn] account: ${sub} signed up with ${c.id} (${c.label}) → ${c.audiences.join(', ')}`);
    return { code: c, account };
  }

  // ── Google ──

  private googleStart(url: URL, res: ServerResponse): void {
    const state = url.searchParams.get('state') ?? '';
    if (!this.states.get(state)) {
      return html(res, 400, page('login expired', '<p>Login attempt expired or invalid — start again from the service.</p>'));
    }
    if (!this.googleOn) return html(res, 503, page('login unavailable', '<p>Google login is not configured on this node.</p>'));
    this.toGoogle(res, state);
  }

  private toGoogle(res: ServerResponse, state: string): void {
    const st = this.states.get(state)!;
    st.pkce = newPkceVerifier(); // a fresh one per trip to Google
    redirect(res, googleAuthorizeUrl(this.d.cfg.googleClientId!, this.googleCallbackUrl, state, st.pkce));
  }

  private async googleCallback(req: IncomingMessage, url: URL, res: ServerResponse): Promise<void> {
    const st = this.states.take(url.searchParams.get('state') ?? ''); // single-use, success or not
    if (!st) {
      return html(res, 400, page('login expired', '<p>Login attempt expired or invalid — start again from the service.</p>'));
    }
    if (st.intent === 'link') {
      res.setHeader('set-cookie', this.linkCookie('', 0, '/oauth/google/callback')); // spent either way
      if (st.provider !== 'google' || !safeEqual(cookie(req, LINK_COOKIE), st.nonce)) {
        console.error(`[hn] google link refused for ${st.sub}: wrong provider, or finished in a browser that didn't start it`);
        return html(res, 403, page('link refused', '<p>Linking Google has to finish in the same browser that started it. Start again from your <a href="/login?audience=account">sign-in settings</a>.</p>'));
      }
    }
    const code = url.searchParams.get('code') ?? '';
    if (!code || !st.pkce || !this.googleOn) {
      const cancelled = url.searchParams.get('error') === 'access_denied';
      return html(res, 400, page('login failed', `<p>${cancelled ? 'Google sign-in was cancelled.' : 'Google did not complete the sign-in.'} Start again from the service.</p>`));
    }
    let g: GoogleIdentity;
    try {
      g = await completeGoogle(
        { clientId: this.d.cfg.googleClientId!, clientSecret: this.d.cfg.googleClientSecret!, redirectUri: this.googleCallbackUrl, code, verifier: st.pkce },
        this.d.fetchImpl,
      );
    } catch (err) {
      console.error(`[hn] google sign-in failed: ${(err as Error).message}`);
      return html(res, 502, page('login failed', '<p>Google sign-in didn’t go through. Start again from the service.</p>'));
    }
    const label = g.email ?? g.name ?? `Google account ${g.sub}`;
    const now = new Date().toISOString();

    if (st.intent === 'link') {
      const other = this.d.accounts.byGoogle(g.sub);
      if (other && other.sub !== st.sub) {
        return html(res, 409, page('already linked', `<p>That Google account (<b>${esc(label)}</b>) is already linked to another account here.</p>`));
      }
      let acct: HumanAccount | undefined;
      try {
        acct = this.d.accounts.update(st.sub, (a) => {
          if (a.disabled || (a.google?.sub && a.google.sub !== g.sub)) throw new Error('account changed');
          return { ...a, google: googleLink(g, now, a.google?.email) };
        });
      } catch {
        acct = undefined;
      }
      if (!acct) return html(res, 400, page('link failed', '<p>That account can’t take a Google link right now. Start again from your sign-in settings.</p>'));
      console.error(`[hn] account: ${acct.sub} linked google:${g.sub} (${label})`);
      const out = this.issue('account', { sub: acct.sub, name: displayName(acct), grant: this.storedGrant(acct), account: acct }, 'google');
      return out.ok ? redirect(res, out.redirect) : html(res, out.status, page('no access', `<p>${esc(out.error)}</p>`));
    }

    let acct = this.d.accounts.byGoogle(g.sub);
    if (!acct && g.email && g.emailVerified) {
      // An operator invite by address: the first verified sign-in claims it.
      const inv = this.d.accounts.byGoogleInvite(g.email);
      if (inv && !inv.disabled) {
        try {
          acct = this.d.accounts.update(inv.sub, (a) => {
            if (a.disabled || !a.google || a.google.sub || emailKey(a.google.email) !== emailKey(g.email!)) throw new Error('changed');
            return { ...a, google: googleLink(g, now) };
          });
          if (acct) console.error(`[hn] account: ${acct.sub} claimed by google:${g.sub} (${g.email})`);
        } catch {
          acct = undefined;
        }
      } else if (inv) acct = inv; // disabled: refused just below
    }
    let fresh = false;
    if (!acct && !st.code && g.emailVerified && anyOpen(this.d.audiences.get())) {
      // This node is open to newcomers somewhere: a Google account we don't
      // know gets its row on first sign-in, wherever it started. The row
      // holds nothing — an open audience lets it in, everywhere else it is
      // refused with a pointer to what IS open (issue() decides, as for anyone).
      // Verified addresses only: a row keyed on this Google account would
      // shadow an operator invite to that address before it could be claimed.
      try {
        acct = this.d.accounts.add({
          sub: `human:google:${g.sub}`, createdAt: now, notes: `signed up at ${st.audience}`,
          google: googleLink(g, now),
        });
        console.error(`[hn] account: human:google:${g.sub} (${label}) signed up at ${st.audience}`);
      } catch {
        acct = this.d.accounts.bySub(`human:google:${g.sub}`) ?? this.d.accounts.byGoogle(g.sub);
      }
      fresh = true;
    }
    if (!acct && st.code) {
      // Signing up: a Google account we don't know, with an access code.
      const r = this.signUp(`human:google:${g.sub}`, st.code, { google: googleLink(g, now) });
      if (typeof r === 'string') return html(res, 403, page('code not accepted', `<p>${esc(cap(rejectionText(r)))}.</p>`));
      acct = r.account;
      fresh = true;
    }
    if (!acct) {
      console.error(`[hn] login refused: google:${g.sub} (${label}) at ${st.audience} — not linked to an account`);
      return html(res, 403, page('no account', `<p>Hi <b>${esc(label)}</b> — this Google account isn’t linked to an account here.
If you were given an access code, enter it on the sign-in page first. If you have an account, sign in another way and link Google under <a href="/login?audience=account">sign-in settings</a>; otherwise ask an operator.</p>`));
    }
    if (acct.disabled) {
      console.error(`[hn] login refused: ${acct.sub} via google — account disabled`);
      return html(res, 403, page('account disabled', '<p>This account is disabled. Ask an operator.</p>'));
    }
    if (st.code && !fresh) {
      const r = this.redeemInto(acct.sub, st.code);
      if (typeof r === 'string') return html(res, 403, page('code not accepted', `<p>${esc(cap(rejectionText(r)))}. Sign in without it, or ask for a new code.</p>`));
      acct = r.account;
    }
    const seen = acct.google;
    if (
      seen?.sub === g.sub &&
      ((g.email && (g.email !== seen.email || g.emailVerified !== Boolean(seen.verified))) || (g.name && g.name !== seen.name))
    ) {
      try {
        acct = this.d.accounts.update(acct.sub, (a) => {
          if (a.google?.sub !== g.sub) return a;
          const next = { ...a.google, ...(g.name ? { name: g.name } : {}) };
          if (g.email) {
            next.email = g.email;
            if (g.emailVerified) next.verified = true;
            else delete next.verified;
          }
          return { ...a, google: next };
        }) ?? acct;
      } catch {
        /* a new address that clashes with someone's invite: keep the old one on file */
      }
    }
    const who = await this.resolve(acct);
    if (this.d.accounts.bySub(acct.sub)?.disabled) return html(res, 403, page('account disabled', '<p>This account is disabled. Ask an operator.</p>'));
    const out = this.issue(st.audience, who, 'google');
    if (out.ok) return redirect(res, out.redirect);
    console.error(`[hn] login refused: ${acct.sub} via google at ${st.audience} — ${out.error}`);
    return html(res, out.status, page('no access', `<p>Hi <b>${esc(who.name)}</b> — you’re signed in, but this account doesn’t have access to <b>${esc(st.audience)}</b> (${esc(out.error)}). Ask an operator for access, then try again.</p>${this.openHint(st.audience)}`));
  }

  private googleLink(res: ServerResponse, t: Aid1Payload): void {
    if (!this.googleOn) return json(res, 400, { error: 'Google login is not configured on this node' });
    const a = this.ensureAccount(t);
    if (!a) return json(res, 404, { error: 'no account' });
    if (a.google?.sub) return json(res, 400, { error: 'a Google account is already linked — unlink it first' });
    const nonce = randomBytes(24).toString('base64url');
    const state = this.newState({ intent: 'link', provider: 'google', sub: a.sub, nonce, audience: 'account', exp: Date.now() + STATE_TTL_MS });
    res.setHeader('set-cookie', this.linkCookie(nonce, STATE_TTL_MS / 1000, '/oauth/google/callback'));
    json(res, 200, { url: `${this.d.cfg.publicUrl}/login/google?state=${state}` });
  }

  private googleUnlink(res: ServerResponse, t: Aid1Payload): void {
    const a = this.d.accounts.bySub(t.sub);
    if (!a?.google) return json(res, 400, { error: 'no Google account linked' });
    if (loginMethods(a) <= 1) return json(res, 400, { error: 'that’s your only way to sign in — add another first' });
    this.d.accounts.update(t.sub, (x) => {
      const { google: _g, ...rest } = x;
      return rest;
    });
    console.error(`[hn] account: ${t.sub} unlinked google${a.google.sub ? `:${a.google.sub}` : ` invite (${a.google.email})`}`);
    json(res, 200, this.view(t));
  }

  // ── one-time setup links ──

  private setupAccount(code: unknown): HumanAccount | null {
    if (typeof code !== 'string' || code.length < 20) return null;
    const h = sha256hex(code);
    const a = this.d.accounts.all().find((x) => x.setup?.hash === h);
    if (!a || !a.setup || Date.parse(a.setup.exp) <= Date.now() || a.disabled) return null;
    return a;
  }

  private setupInfo(res: ServerResponse, b: Record<string, unknown>): void {
    const a = this.setupAccount(b.code);
    if (!a) return json(res, 404, { error: 'this setup link is invalid, used, or expired — ask the operator for a new one' });
    json(res, 200, { username: a.username ?? null, name: displayName(a), needsTotp: Boolean(a.totp), needsUsername: !a.username });
  }

  private async setupFinish(res: ServerResponse, b: Record<string, unknown>): Promise<void> {
    const a = this.setupAccount(b.code);
    if (!a) return json(res, 404, { error: 'this setup link is invalid, used, or expired — ask the operator for a new one' });
    let username = a.username;
    if (!username) {
      const want = normalizeUsername(String(b.username ?? ''));
      const bad = usernameProblem(want, this.d.accounts, (n) => this.d.principals.nameTaken(n), a.sub);
      if (bad) return json(res, 400, { error: bad });
      username = want;
    }
    const bad = passwordProblem(b.password, username);
    if (bad) return json(res, 400, { error: bad });
    // A reset link doesn't get around two-factor that's still on.
    if (a.totp) {
      const check = this.checkSecondFactor(a, String(b.totp ?? ''));
      if (check === 'locked') return json(res, 429, { error: 'too many wrong codes — wait 15 minutes' });
      if (check === 'bad') return json(res, 401, { error: 'enter the code from your authenticator app (or a recovery code)' });
    }
    const hash = await hashPassword(String(b.password));
    // Consumed under the store lock, against the file as it is now: a link
    // raced by two requests (or reset by the CLI meanwhile) works once.
    let acct: HumanAccount | undefined;
    try {
      acct = this.d.accounts.update(a.sub, (x) => {
        if (x.setup?.hash !== a.setup!.hash || Date.parse(x.setup.exp) <= Date.now() || x.disabled) throw new Error('used');
        const { setup: _s, ...rest } = x;
        return { ...rest, username: x.username ?? username, password: hash };
      });
    } catch (err) {
      const msg = (err as Error).message;
      return msg === 'used'
        ? json(res, 404, { error: 'this setup link is invalid, used, or expired — ask the operator for a new one' })
        : json(res, 409, { error: msg }); // e.g. the username was just taken
    }
    if (!acct) return json(res, 404, { error: 'this setup link is invalid, used, or expired — ask the operator for a new one' });
    console.error(`[hn] account: ${acct.sub} completed setup link (username ${username})`);
    this.respond(res, this.issue('account', { sub: acct.sub, name: displayName(acct), grant: this.storedGrant(acct), account: acct }, 'setup'));
  }
}

const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

function cookie(req: IncomingMessage, name: string): string {
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return '';
}

function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && x.length > 0 && timingSafeEqual(x, y);
}
