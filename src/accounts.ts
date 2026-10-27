/**
 * Human accounts — the home's own login, beside Discord.
 *
 * Discord-only humans still need no row here: they are derived from Discord
 * at login, exactly as before. A row exists once a person wants another way
 * in (username + password, a passkey, TOTP) or the operator creates someone
 * who has no Discord at all. One row = one person = one `sub`, however they
 * sign in:
 *
 *   human:discord:<snowflake>   row made from a Discord login — the sub they
 *                               always had, so nothing keyed to it moves
 *   human:local:<username>      row made by the operator (`hn user add`)
 *
 * The sub is fixed at creation. Login methods attach to it and come and go;
 * a Discord-anchored row can't drop its Discord link (that link IS its sub).
 *
 * Scopes: the Discord leg still decides what a Discord-linked person holds
 * (roles → scopes, read live at Discord login, or by bot lookup / a recent
 * snapshot on other logins); `scopes` here is an operator grant on top, and
 * the only grant a local-only account has.
 */
import { createHash, randomBytes, scrypt as scryptCb, timingSafeEqual, type JsonWebKey } from 'node:crypto';
import { JsonStore, type RoleGrant } from './stores.js';

// ── record ──

export interface Passkey {
  /** Credential id, base64url. */
  id: string;
  jwk: JsonWebKey;
  /** COSE algorithm: -8 EdDSA, -7 ES256, -257 RS256. */
  alg: number;
  signCount: number;
  name: string;
  createdAt: string;
  lastUsedAt?: string;
}

export interface HumanAccount {
  sub: string;
  /** Login handle — lowercase, unique across accounts AND principal names. */
  username?: string;
  /** Display-name override; absent = Discord name (Discord rows) or username. */
  name?: string;
  discord?: {
    id: string;
    /** Display name at the last Discord check. */
    name?: string;
    /** Role grant at the last Discord check (null = in no qualifying role). */
    grant?: RoleGrant | null;
    checkedAt?: string;
  };
  /** `scrypt$<logN>$<r>$<p>$<salt>$<hash>` */
  password?: string;
  totp?: { secret: string; lastStep?: number; enabledAt: string };
  /** sha256 (hex) of each unused recovery code. */
  recovery?: string[];
  passkeys?: Passkey[];
  /** WebAuthn user handle (random, base64url) — what a passkey stores as `user.id`. */
  webauthnUserId?: string;
  /** Operator grant, unioned with whatever Discord grants. */
  scopes?: string[];
  claims?: Record<string, unknown>;
  /** One-time setup link (hn user add / reset): sha256 of the code + expiry. */
  setup?: { hash: string; exp: string };
  disabled?: boolean;
  createdAt: string;
  notes?: string;
}

export interface AccountsFile {
  accounts: HumanAccount[];
}

function validateAccounts(raw: unknown): AccountsFile | null {
  return accountsProblem(raw) ? null : (raw as AccountsFile);
}

/** Why a file can't be loaded (or written), or null. Writes are checked
 *  too, so a race can't leave a file the next start would refuse. */
function accountsProblem(raw: unknown): string | null {
  const f = raw as AccountsFile;
  if (!f || !Array.isArray(f.accounts)) return 'not an accounts file';
  const subs = new Set<string>();
  const names = new Set<string>();
  const discords = new Set<string>();
  const passkeys = new Set<string>();
  for (const a of f.accounts) {
    if (typeof a.sub !== 'string' || !a.sub.startsWith('human:')) return 'bad sub';
    if (subs.has(a.sub)) return `duplicate sub ${a.sub}`;
    subs.add(a.sub);
    if (a.username !== undefined) {
      if (typeof a.username !== 'string') return 'bad username';
      if (names.has(a.username)) return `username "${a.username}" is taken`;
      names.add(a.username);
    }
    if (a.discord) {
      if (discords.has(a.discord.id)) return 'that Discord account is linked elsewhere';
      discords.add(a.discord.id);
    }
    for (const p of a.passkeys ?? []) {
      if (passkeys.has(p.id)) return 'that passkey is already registered';
      passkeys.add(p.id);
    }
    if (a.scopes !== undefined && (!Array.isArray(a.scopes) || !a.scopes.every((s) => typeof s === 'string'))) return 'bad scopes';
  }
  return null;
}

// ── store ──

export class AccountStore {
  private store: JsonStore<AccountsFile>;

  constructor(path: string) {
    // 0600: password hashes and TOTP secrets live here.
    this.store = new JsonStore(path, validateAccounts, { accounts: [] }, 'accounts', 0o600);
  }

  startWatching(): void {
    this.store.startWatching();
  }
  stopWatching(): void {
    this.store.stopWatching();
  }

  /** Always current: picks up an `hn user …` edit made a moment ago. */
  all(): HumanAccount[] {
    this.store.refresh();
    return this.store.get().accounts;
  }

  bySub(sub: string): HumanAccount | undefined {
    return this.all().find((a) => a.sub === sub);
  }
  byUsername(username: string): HumanAccount | undefined {
    const u = normalizeUsername(username);
    return this.all().find((a) => a.username === u);
  }
  byDiscord(id: string): HumanAccount | undefined {
    return this.all().find((a) => a.discord?.id === id);
  }
  byPasskey(credentialId: string): { account: HumanAccount; passkey: Passkey } | undefined {
    for (const account of this.all()) {
      const passkey = account.passkeys?.find((p) => p.id === credentialId);
      if (passkey) return { account, passkey };
    }
    return undefined;
  }

  /** A username or display-name override already in use (case-insensitive). */
  nameTaken(name: string): boolean {
    const n = name.trim().toLowerCase();
    return this.all().some((a) => a.username === n || a.name?.toLowerCase() === n);
  }

  /** Throws (writing nothing) on a duplicate sub, username, Discord link or passkey. */
  add(a: HumanAccount): HumanAccount {
    this.store.update((f) => {
      if (f.accounts.some((x) => x.sub === a.sub)) throw new Error(`account ${a.sub} exists`);
      return checked({ accounts: [...f.accounts, a] });
    });
    return a;
  }

  /**
   * Read-modify-write of one account against the file as it is now, under a
   * lock the hn CLI shares, so neither side drops the other's change. `fn`
   * returns the new record, or throws to abort (nothing written). Throws if
   * the result would duplicate a username, Discord link or passkey.
   */
  update(sub: string, fn: (a: HumanAccount) => HumanAccount): HumanAccount | undefined {
    let next: HumanAccount | undefined;
    this.store.update((f) => {
      const cur = f.accounts.find((a) => a.sub === sub);
      if (!cur) return f;
      next = fn(structuredClone(cur));
      return checked({ accounts: f.accounts.map((a) => (a.sub === sub ? next! : a)) });
    });
    return next;
  }
}

function checked(f: AccountsFile): AccountsFile {
  const bad = accountsProblem(f);
  if (bad) throw new Error(bad);
  return f;
}

// ── usernames ──

const USERNAME_RE = /^[a-z0-9](?:[a-z0-9._-]{1,30})[a-z0-9]$/;
const RESERVED = new Set([
  'admin', 'administrator', 'root', 'system', 'operator', 'guest', 'anonymous', 'discord', 'local', 'console',
  'account', 'home', 'support', 'security', 'staff', 'everyone', 'here',
]);

export function normalizeUsername(u: string): string {
  return u.trim().toLowerCase();
}

/** Why a username can't be used, or null. `takenElsewhere` checks names
 *  held outside the account store (principal display names: an agent
 *  called "fable" means no human may log in as "fable"). */
export function usernameProblem(raw: string, accounts: AccountStore, takenElsewhere: (n: string) => boolean): string | null {
  const u = normalizeUsername(raw);
  if (!USERNAME_RE.test(u)) return 'usernames are 3–32 characters: a–z, 0–9, and . _ - (not at the ends)';
  if (RESERVED.has(u)) return 'that username is reserved';
  if (accounts.nameTaken(u) || takenElsewhere(u)) return 'that username is taken';
  return null;
}

// ── passwords (scrypt, async so a login never stalls the event loop) ──

const SCRYPT_LOG_N = 15;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEYLEN = 32;

function scrypt(pw: string, salt: Buffer, logN: number, r: number, p: number): Promise<Buffer> {
  return new Promise((resolve, reject) =>
    scryptCb(pw.normalize('NFKC'), salt, KEYLEN, { N: 2 ** logN, r, p, maxmem: 256 * 2 ** logN * r + 1024 * 1024 }, (err, key) =>
      err ? reject(err) : resolve(key),
    ),
  );
}

export async function hashPassword(pw: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await scrypt(pw, salt, SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P);
  return `scrypt$${SCRYPT_LOG_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString('base64url')}$${key.toString('base64url')}`;
}

export async function verifyPassword(pw: string, stored: string | undefined): Promise<boolean> {
  // An account without a password still costs one scrypt, so response time
  // doesn't tell a prober which usernames exist or have passwords.
  const parts = (stored ?? DUMMY_HASH).split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, logN, r, p, salt, hash] = parts as [string, string, string, string, string, string];
  const want = Buffer.from(hash, 'base64url');
  const got = await scrypt(pw, Buffer.from(salt, 'base64url'), Number(logN), Number(r), Number(p));
  return stored !== undefined && got.length === want.length && timingSafeEqual(got, want);
}
const DUMMY_HASH = `scrypt$${SCRYPT_LOG_N}$${SCRYPT_R}$${SCRYPT_P}$${'A'.repeat(22)}$${'A'.repeat(43)}`;

export function passwordProblem(pw: unknown, username?: string): string | null {
  if (typeof pw !== 'string') return 'password required';
  if ([...pw].length < 10) return 'passwords need at least 10 characters';
  if (pw.length > 256) return 'password too long';
  // The username doesn't count toward the length: "alice-2024" for alice is 5 characters of password.
  if (username && [...pw.toLowerCase().split(username.toLowerCase()).join('')].length < 10) {
    return 'passwords need at least 10 characters besides your username';
  }
  return null;
}

// ── recovery + setup codes ──

const RC_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789'; // no 0/o/1/l/i

function randomCode(len: number): string {
  const bytes = randomBytes(len);
  return [...bytes].map((b) => RC_ALPHABET[b % RC_ALPHABET.length]).join('');
}

export function sha256hex(s: string): string {
  return createHash('sha256').update(s).digest('hex');
}

/** Ten single-use codes, `xxxxx-xxxxx` (~49 bits each). Returns the codes
 *  to show once and the hashes to store. */
export function newRecoveryCodes(n = 10): { codes: string[]; hashes: string[] } {
  const codes = Array.from({ length: n }, () => {
    const c = randomCode(10);
    return `${c.slice(0, 5)}-${c.slice(5)}`;
  });
  return { codes, hashes: codes.map((c) => sha256hex(normalizeRecovery(c))) };
}

export function normalizeRecovery(code: string): string {
  return code.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/** Ten characters once spaces and dashes go — never mistaken for a 6-digit
 *  TOTP code, whatever mix of letters and digits it drew. */
export function looksLikeRecoveryCode(code: string): boolean {
  return normalizeRecovery(code).length === 10;
}

export const SETUP_LIFETIME_MS = 72 * 3_600_000;

export function newSetupCode(nowMs = Date.now()): { code: string; setup: { hash: string; exp: string } } {
  const code = randomBytes(24).toString('base64url');
  return { code, setup: { hash: sha256hex(code), exp: new Date(nowMs + SETUP_LIFETIME_MS).toISOString() } };
}

// ── grants ──

/** Discord snapshots this old stop counting for non-Discord logins when no
 *  bot token is configured to re-check live: a removed role takes effect on
 *  password/passkey logins within this window. */
export const DISCORD_SNAPSHOT_MAX_AGE_MS = 7 * 86_400_000;

export function mergeGrants(...grants: Array<RoleGrant | null | undefined>): RoleGrant | null {
  const scopes = new Set<string>();
  let claims: Record<string, unknown> = {};
  let any = false;
  for (const g of grants) {
    if (!g) continue;
    any = true;
    for (const s of g.scopes) scopes.add(s);
    claims = { ...claims, ...g.claims };
  }
  if (!any) return null;
  return { scopes: [...scopes], ...(Object.keys(claims).length ? { claims } : {}) };
}

export function operatorGrant(a: HumanAccount | undefined): RoleGrant | null {
  if (!a?.scopes?.length && !a?.claims) return null;
  return { scopes: a.scopes ?? [], ...(a.claims ? { claims: a.claims } : {}) };
}

/** Override → the anchor's own name (Discord name for a Discord-anchored
 *  row, username for a local one) → whatever else there is. */
export function displayName(a: HumanAccount): string {
  const anchored = a.sub.startsWith('human:discord:') ? a.discord?.name : a.username;
  return (a.name || anchored || a.username || a.discord?.name || a.sub).slice(0, 32);
}

/** Login methods still standing — an account must always keep one. */
export function loginMethods(a: HumanAccount): number {
  return (a.password ? 1 : 0) + (a.passkeys?.length ?? 0) + (a.discord ? 1 : 0);
}
