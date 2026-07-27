/**
 * Discord OAuth2 (auth-code flow) — the human leg (docs/home-node.md §3).
 * Cribbed from portal-relay src/admin/oauth.ts, with one change: instead of
 * deriving admin guilds we fetch the user's member object in OUR guild
 * (`guilds.members.read` scope → GET /users/@me/guilds/<id>/member), which
 * carries their role ids. No bot needed. The user's Discord token is used
 * for the two lookups and discarded — never stored.
 */

export const OAUTH_SCOPES = 'identify guilds.members.read';
const AUTHORIZE_URL = 'https://discord.com/oauth2/authorize';
const TOKEN_URL = 'https://discord.com/api/oauth2/token';
const API_BASE = 'https://discord.com/api';

export interface DiscordUser {
  id: string;
  username: string;
  global_name?: string | null;
}

export interface GuildMember {
  roles: string[];
  nick?: string | null;
}

export interface OAuthResult {
  user: DiscordUser;
  /** null = not a member of the guild. */
  member: GuildMember | null;
}

export function authorizeUrl(clientId: string, redirectUri: string, state: string): string {
  const q = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: OAUTH_SCOPES,
    state,
  });
  return `${AUTHORIZE_URL}?${q.toString()}`;
}

export type FetchLike = typeof fetch;

export async function completeOAuth(
  opts: {
    clientId: string;
    clientSecret: string;
    redirectUri: string;
    code: string;
    guildId: string;
  },
  fetchImpl: FetchLike = fetch,
): Promise<OAuthResult> {
  const body = new URLSearchParams({
    client_id: opts.clientId,
    client_secret: opts.clientSecret,
    grant_type: 'authorization_code',
    code: opts.code,
    redirect_uri: opts.redirectUri,
  });
  const tokenRes = await fetchImpl(TOKEN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  if (!tokenRes.ok) throw new Error(`oauth token exchange failed: ${tokenRes.status}`);
  const tok = (await tokenRes.json()) as { access_token?: string; token_type?: string };
  if (!tok.access_token) throw new Error('oauth token exchange: no access_token');
  const auth = `${tok.token_type ?? 'Bearer'} ${tok.access_token}`;

  const user = await apiGet<DiscordUser>(`${API_BASE}/users/@me`, auth, fetchImpl);
  if (!user?.id) throw new Error('oauth: malformed /users/@me');

  // 404 here = authenticated fine but not in the guild — a policy outcome,
  // not an error.
  let member: GuildMember | null = null;
  const memberRes = await fetchImpl(`${API_BASE}/users/@me/guilds/${opts.guildId}/member`, {
    headers: { authorization: auth },
  });
  if (memberRes.ok) {
    const m = (await memberRes.json()) as GuildMember;
    if (Array.isArray(m?.roles)) member = m;
  } else if (memberRes.status !== 404) {
    throw new Error(`oauth member lookup failed: ${memberRes.status}`);
  }

  return { user, member };
}

/** Preferred display name: guild nick → global name → username. */
export function displayNameOf(user: DiscordUser, member: GuildMember | null): string {
  return (member?.nick || user.global_name || user.username || `discord-${user.id}`).slice(0, 32);
}

async function apiGet<T>(url: string, auth: string, fetchImpl: FetchLike): Promise<T> {
  const res = await fetchImpl(url, { headers: { authorization: auth } });
  if (!res.ok) throw new Error(`oauth GET ${url} failed: ${res.status}`);
  return (await res.json()) as T;
}
