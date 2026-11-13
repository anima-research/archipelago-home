/**
 * Google sign-in: OpenID Connect, auth-code flow with PKCE, scopes
 * `openid email profile` only (Google's non-sensitive tier: no app review).
 *
 * Google carries no roles, so a Google login grants nothing by itself: it
 * opens an account that already exists here — one that linked Google under
 * sign-in settings, or one the operator made with `hn user add <name>
 * --google <email>`, which the first sign-in with that verified address
 * claims. A Google account we don't know is refused; there is no sign-up.
 *
 * The id_token comes straight from Google's token endpoint over TLS in
 * exchange for our client secret, so its signature isn't checked here
 * (OIDC Core §3.1.3.7); iss, aud and exp are. Google's tokens are used
 * once and discarded — never stored.
 */
import { createHash, randomBytes } from 'node:crypto';
import type { FetchLike } from './oauth.js';

const AUTHORIZE_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const ISSUERS = new Set(['https://accounts.google.com', 'accounts.google.com']);
export const GOOGLE_SCOPES = 'openid email profile';

export interface GoogleIdentity {
  /** Google's stable account id — what a link is keyed by. */
  sub: string;
  email?: string;
  emailVerified: boolean;
  name?: string;
}

export function newPkceVerifier(): string {
  return randomBytes(32).toString('base64url');
}

export function googleAuthorizeUrl(clientId: string, redirectUri: string, state: string, verifier: string): string {
  const q = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: GOOGLE_SCOPES,
    state,
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    // people with several Google accounts pick one, every time
    prompt: 'select_account',
  });
  return `${AUTHORIZE_URL}?${q.toString()}`;
}

export async function completeGoogle(
  opts: { clientId: string; clientSecret: string; redirectUri: string; code: string; verifier: string },
  fetchImpl: FetchLike = fetch,
): Promise<GoogleIdentity> {
  const body = new URLSearchParams({
    client_id: opts.clientId,
    client_secret: opts.clientSecret,
    grant_type: 'authorization_code',
    code: opts.code,
    redirect_uri: opts.redirectUri,
    code_verifier: opts.verifier,
  });
  const res = await fetchImpl(TOKEN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  if (!res.ok) throw new Error(`google token exchange failed: ${res.status}`);
  const tok = (await res.json()) as { id_token?: string };
  if (!tok.id_token) throw new Error('google token exchange: no id_token');
  return identityFromIdToken(tok.id_token, opts.clientId);
}

export function identityFromIdToken(idToken: string, clientId: string, nowS = Math.floor(Date.now() / 1000)): GoogleIdentity {
  const part = idToken.split('.')[1];
  let c: Record<string, unknown>;
  try {
    c = JSON.parse(Buffer.from(part ?? '', 'base64url').toString('utf8')) as Record<string, unknown>;
  } catch {
    throw new Error('google id_token: unreadable');
  }
  if (!ISSUERS.has(String(c.iss))) throw new Error('google id_token: wrong issuer');
  const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
  if (!aud.includes(clientId)) throw new Error('google id_token: not for this client');
  if (typeof c.exp !== 'number' || c.exp < nowS - 60) throw new Error('google id_token: expired');
  if (typeof c.sub !== 'string' || !c.sub) throw new Error('google id_token: no sub');
  return {
    sub: c.sub,
    ...(typeof c.email === 'string' ? { email: c.email } : {}),
    emailVerified: c.email_verified === true || c.email_verified === 'true',
    ...(typeof c.name === 'string' && c.name ? { name: c.name.slice(0, 64) } : {}),
  };
}

/**
 * How an operator-typed address is compared with the one Google reports:
 * case-insensitive, and for Gmail the way Gmail delivers (dots and a
 * +suffix in the local part don't change the mailbox).
 */
export function emailKey(email: string): string {
  const e = email.trim().toLowerCase();
  const at = e.lastIndexOf('@');
  if (at < 1) return e;
  let local = e.slice(0, at);
  const domain = e.slice(at + 1);
  if (domain === 'gmail.com' || domain === 'googlemail.com') {
    local = local.split('+')[0]!.replace(/\./g, '');
    return `${local}@gmail.com`;
  }
  return `${local}@${domain}`;
}

export function looksLikeEmail(s: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s.trim());
}
