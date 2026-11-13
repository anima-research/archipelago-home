/**
 * Hot-reloaded JSON stores — the thrice-proven pattern (discord-mcpl
 * filters → fkm observers → portal): atomic tmp+rename writes, mtime poll,
 * parse-error-keeps-previous. Plus the append-only mint audit log.
 */
import {
  appendFileSync,
  chmodSync,
  closeSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import type { PrincipalKind } from './token.js';

// ---------------------------------------------------------------------------
// Generic watched JSON file
// ---------------------------------------------------------------------------

export class JsonStore<T> {
  private value: T;
  private lastMtime: number | null = null;
  private poll: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly path: string,
    private readonly validate: (raw: unknown) => T | null,
    private readonly empty: T,
    private readonly label: string,
    /** File mode for writes (e.g. 0o600 for credential files). */
    private readonly mode?: number,
  ) {
    this.value = this.loadOnce() ?? empty;
  }

  private loadOnce(): T | null {
    try {
      const raw = JSON.parse(readFileSync(this.path, 'utf8')) as unknown;
      const v = this.validate(raw);
      if (v === null) console.error(`[hn] ${this.label}: ${this.path} failed validation`);
      this.lastMtime = statSync(this.path).mtimeMs;
      return v;
    } catch {
      return null; // missing/unparseable → caller keeps empty/previous
    }
  }

  startWatching(intervalMs = 3000): void {
    this.poll = setInterval(() => {
      let m: number | null = null;
      try {
        m = statSync(this.path).mtimeMs;
      } catch {
        return; // missing or mid-rename
      }
      if (m === this.lastMtime) return;
      this.lastMtime = m;
      const next = this.loadOnce();
      if (next === null) {
        console.error(`[hn] ${this.label}: ${this.path} unparseable — keeping previous`);
        return;
      }
      this.value = next;
      console.error(`[hn] ${this.label}: reloaded`);
    }, intervalMs);
    this.poll.unref();
  }

  stopWatching(): void {
    if (this.poll) clearInterval(this.poll);
  }

  /** Pick up an out-of-process write (the hn CLI) now rather than at the next
   *  poll — a stat when nothing changed. Call before a read-modify-write so a
   *  concurrent CLI edit isn't clobbered. */
  refresh(): void {
    let m: number;
    try {
      m = statSync(this.path).mtimeMs;
    } catch {
      return;
    }
    if (m === this.lastMtime) return;
    const next = this.loadOnce();
    if (next !== null) this.value = next;
  }

  get(): T {
    return this.value;
  }

  /**
   * Read-modify-write under a lock shared with other processes (an O_EXCL
   * lock file beside the data file), re-reading the file inside the lock —
   * for stores that both the server and the hn CLI write, so neither drops
   * the other's change. `fn` throwing aborts with nothing written; `fn`
   * returning its argument unchanged writes nothing either.
   */
  update(fn: (cur: T) => T): T {
    return withFileLock(`${this.path}.lock`, () => {
      const fresh = this.loadOnce();
      if (fresh !== null) this.value = fresh;
      const next = fn(this.value);
      if (next !== this.value) this.set(next); // fn returning its input = nothing changed, nothing written
      return next;
    });
  }

  /** Atomic write-through (tmp+rename); pollers never see a half-write. */
  set(next: T): void {
    this.value = next;
    mkdirSync(dirname(this.path), { recursive: true });
    // Per-writer tmp name: the server and the CLI never share one.
    const tmp = `${this.path}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
    writeFileSync(tmp, JSON.stringify(next, null, 2) + '\n', this.mode !== undefined ? { mode: this.mode } : undefined);
    if (this.mode !== undefined) chmodSync(tmp, this.mode); // mode only applies on create
    renameSync(tmp, this.path);
    try {
      this.lastMtime = statSync(this.path).mtimeMs; // suppress self-reload
    } catch {
      /* ignore */
    }
  }
}

const LOCK_WAIT_MS = 5_000;
const LOCK_STALE_MS = 10_000;
const sleeper = new Int32Array(new SharedArrayBuffer(4));

/** Run `fn` holding `lockPath` (created O_EXCL). Holders keep it for a
 *  read-parse-write — milliseconds — so waiters spin briefly; a lock older
 *  than LOCK_STALE_MS is a crashed holder's and is broken. */
export function withFileLock<R>(lockPath: string, fn: () => R): R {
  const deadline = Date.now() + LOCK_WAIT_MS;
  let fd: number | null = null;
  while (fd === null) {
    try {
      mkdirSync(dirname(lockPath), { recursive: true });
      fd = openSync(lockPath, 'wx', 0o600);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
      try {
        if (Date.now() - statSync(lockPath).mtimeMs > LOCK_STALE_MS) {
          unlinkSync(lockPath);
          continue;
        }
      } catch {
        continue; // released between our open and stat
      }
      if (Date.now() > deadline) throw new Error(`${lockPath} held for over ${LOCK_WAIT_MS} ms`);
      Atomics.wait(sleeper, 0, 0, 5);
    }
  }
  try {
    return fn();
  } finally {
    closeSync(fd);
    try {
      unlinkSync(lockPath);
    } catch {
      /* already gone */
    }
  }
}

// ---------------------------------------------------------------------------
// Principals
// ---------------------------------------------------------------------------

export interface Principal {
  /** Durable id: `agent:<name>@<domain>` / `service:<name>@<domain>`. */
  sub: string;
  /** Display name — unique (case-insensitive) across principals. */
  name: string;
  kind: PrincipalKind;
  /** `ed25519:<b64url>` — null for manual-token-only guests. */
  key?: string | null;
  scopes: string[];
  claims?: Record<string, unknown>;
  /** Audiences this principal may request tokens for; absent = any. */
  audiences?: string[];
  /** Lifetime of tokens minted via /token (e.g. "14d"); default 7d. */
  tokenTtl?: string;
  /** ISO — principal expired means no further token issuance. */
  expires?: string | null;
  notes?: string;
}

export interface PrincipalsFile {
  principals: Principal[];
}

function validatePrincipals(raw: unknown): PrincipalsFile | null {
  const f = raw as PrincipalsFile;
  if (!f || !Array.isArray(f.principals)) return null;
  for (const p of f.principals) {
    if (typeof p.sub !== 'string' || !p.sub) return null;
    if (typeof p.name !== 'string' || !p.name) return null;
    if (p.kind !== 'human' && p.kind !== 'agent' && p.kind !== 'service') return null;
    if (p.key != null && (typeof p.key !== 'string' || !p.key.startsWith('ed25519:'))) return null;
    if (!Array.isArray(p.scopes) || !p.scopes.every((s) => typeof s === 'string')) return null;
  }
  return f;
}

export class PrincipalStore {
  private store: JsonStore<PrincipalsFile>;

  constructor(path: string) {
    this.store = new JsonStore(path, validatePrincipals, { principals: [] }, 'principals');
  }

  startWatching(): void {
    this.store.startWatching();
  }
  stopWatching(): void {
    this.store.stopWatching();
  }

  all(): Principal[] {
    return this.store.get().principals;
  }

  bySub(sub: string): Principal | undefined {
    return this.all().find((p) => p.sub === sub);
  }

  byKey(key: string): Principal | undefined {
    return this.all().find((p) => p.key === key);
  }

  nameTaken(name: string): boolean {
    const n = name.toLowerCase();
    return this.all().some((p) => p.name.toLowerCase() === n);
  }

  isLive(p: Principal, nowMs = Date.now()): boolean {
    return !p.expires || Date.parse(p.expires) > nowMs;
  }

  add(p: Principal): void {
    if (this.bySub(p.sub)) throw new Error(`duplicate sub ${p.sub}`);
    if (this.nameTaken(p.name)) throw new Error(`name "${p.name}" already taken`);
    if (p.key && this.byKey(p.key)) throw new Error(`key already enrolled`);
    this.store.set({ principals: [...this.all(), p] });
  }

  /** Revocation = stop issuance (archipelago rule 2: no CRLs; outstanding
   *  tokens live out their exp). Record kept for audit. */
  revoke(sub: string, nowIso = new Date().toISOString()): boolean {
    const list = this.all();
    const p = list.find((x) => x.sub === sub);
    if (!p) return false;
    this.store.set({
      principals: list.map((x) => (x.sub === sub ? { ...x, expires: nowIso } : x)),
    });
    return true;
  }
}

// ---------------------------------------------------------------------------
// Invites — portal invite semantics (check / consume / mint / revoke)
// ---------------------------------------------------------------------------

export interface Invite {
  code: string;
  label?: string;
  /** Scope stamp for principals enrolled through this invite. */
  scopes: string[];
  claims?: Record<string, unknown>;
  audiences?: string[];
  /** tokenTtl stamped on enrolled principals (default guest policy: short). */
  tokenTtl?: string;
  maxUses?: number;
  uses?: number;
  expiresAt?: string;
  /** Sub of the human who minted this via the console — their vouch. */
  sponsor?: string;
  /**
   * Domain the enrolled principal is anchored to: `agent:<name>@<domain>`.
   * Absent = `guest` (invited, anchored nowhere). Setting it is the home
   * vouching maximally — "we host or directly stand behind this agent" —
   * so it takes the operator (hn CLI) or an `id:anchor` holder in the
   * sponsor console, and carries the full resident grant there.
   */
  domain?: string;
}

export interface InvitesFile {
  invites: Invite[];
}

export type InviteRejection = 'unknown' | 'expired' | 'exhausted';

function validateInvites(raw: unknown): InvitesFile | null {
  const f = raw as InvitesFile;
  if (!f || !Array.isArray(f.invites)) return null;
  const seen = new Set<string>();
  for (const inv of f.invites) {
    if (typeof inv.code !== 'string' || !inv.code || seen.has(inv.code)) return null;
    if (!Array.isArray(inv.scopes)) return null;
    seen.add(inv.code);
  }
  return f;
}

export class InviteStore {
  private store: JsonStore<InvitesFile>;

  constructor(path: string) {
    this.store = new JsonStore(path, validateInvites, { invites: [] }, 'invites');
  }

  startWatching(): void {
    this.store.startWatching();
  }
  stopWatching(): void {
    this.store.stopWatching();
  }

  all(): Invite[] {
    return this.store.get().invites;
  }

  check(code: string, nowMs = Date.now()): Invite | InviteRejection {
    const inv = this.all().find((i) => i.code === code);
    if (!inv) return 'unknown';
    if (inv.expiresAt && Date.parse(inv.expiresAt) <= nowMs) return 'expired';
    if (inv.maxUses !== undefined && (inv.uses ?? 0) >= inv.maxUses) return 'exhausted';
    return inv;
  }

  consume(code: string): void {
    this.store.set({
      invites: this.all().map((i) => (i.code === code ? { ...i, uses: (i.uses ?? 0) + 1 } : i)),
    });
  }

  mint(inv: Omit<Invite, 'code'> & { code?: string }): Invite {
    const code = inv.code ?? `inv_${randomBytes(6).toString('base64url')}`;
    if (this.all().some((i) => i.code === code)) throw new Error(`duplicate invite code ${code}`);
    const full: Invite = { uses: 0, ...inv, code };
    this.store.set({ invites: [...this.all(), full] });
    return full;
  }

  revoke(code: string): boolean {
    const before = this.all();
    const after = before.filter((i) => i.code !== code);
    if (after.length === before.length) return false;
    this.store.set({ invites: after });
    return true;
  }
}

// ---------------------------------------------------------------------------
// Config: roles → scopes, audiences
// ---------------------------------------------------------------------------

export interface RoleGrant {
  scopes: string[];
  claims?: Record<string, unknown>;
}

export interface RolesConfig {
  guildId: string;
  /** Discord role id → grant. */
  map: Record<string, RoleGrant>;
}

export function rolesStore(path: string): JsonStore<RolesConfig> {
  return new JsonStore<RolesConfig>(
    path,
    (raw) => {
      const f = raw as RolesConfig;
      if (!f || typeof f.guildId !== 'string' || typeof f.map !== 'object' || f.map === null) return null;
      return f;
    },
    { guildId: '', map: {} },
    'roles',
  );
}

export interface AudienceConfig {
  /** Where the login token is delivered (URL fragment): e.g. https://worlds…/auth */
  redirect: string;
  /** Scopes a login must have earned (via roles) to get a token for this
   *  audience at all — refusal happens at the login page, with the friendly
   *  "you need the X role" message, instead of at the service. */
  requiredScopes?: string[];
  /** Base URL of the audience's HTTP API, published at `GET /services` so
   *  hosts can resolve audience → base at runtime instead of compiling the
   *  map in. Absent = the audience has no direct HTTP seam (MCPL-only, or
   *  human-login-only) and is omitted from the directory. This file is
   *  hot-reloaded, so adding a service here reaches hosts without a restart
   *  anywhere. */
  api?: string;
  /** The audience's MCPL endpoint (`wss://…`), published at `GET /services`
   *  under `mcpl` so a host can dial the service by audience name — a
   *  resident says `mcpl_deploy {access: "body"}` and the host finds the
   *  address here. Absent = the audience has no MCPL door, or its operator
   *  hasn't published one. wss only, for the same reason as `api`: the host
   *  puts the resident's credential on this dial. */
  mcpl?: string;
}

export type AudiencesConfig = Record<string, AudienceConfig>;

/** The published service directory: audience → API base, for audiences that
 *  declare one. Audiences without an `api` (MCPL-only, or human-login-only)
 *  are simply not in the directory — being listed here is a statement that a
 *  direct HTTP seam exists, never a statement about who may use it. */
export function serviceDirectory(audiences: AudiencesConfig): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, cfg] of Object.entries(audiences ?? {})) {
    const api = cfg?.api;
    // https only: the host attaches a bearer credential to whatever base this
    // resolves to, so a plaintext or malformed base must never enter the map.
    if (typeof api === 'string' && /^https:\/\/[^\s]+$/.test(api)) out[name] = api.replace(/\/+$/, '');
  }
  return out;
}

/** The published MCPL directory: audience → MCPL endpoint, for audiences that
 *  declare one. The same statement as serviceDirectory's, for the other seam:
 *  listed = "an MCPL door exists at this address", never "you may enter".
 *  wss only — a host attaches the resident's credential to this dial, so a
 *  plaintext or malformed endpoint must never enter the map; a host refuses
 *  to send a credential over ws:// to another machine, and this directory is
 *  the operator's word that an endpoint is safe to dial by name. */
export function mcplDirectory(audiences: AudiencesConfig): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, cfg] of Object.entries(audiences ?? {})) {
    const mcpl = cfg?.mcpl;
    if (typeof mcpl === 'string' && /^wss:\/\/[^\s]+$/.test(mcpl)) out[name] = mcpl;
  }
  return out;
}

export function audiencesStore(path: string): JsonStore<AudiencesConfig> {
  return new JsonStore<AudiencesConfig>(
    path,
    (raw) => {
      if (!raw || typeof raw !== 'object') return null;
      for (const v of Object.values(raw as AudiencesConfig)) {
        if (!v || typeof v.redirect !== 'string') return null;
      }
      return raw as AudiencesConfig;
    },
    {},
    'audiences',
  );
}

/** Union of scopes + merged claims for a member's role set. Pure. */
export function grantForRoles(roles: string[], cfg: RolesConfig): RoleGrant | null {
  const scopes = new Set<string>();
  let claims: Record<string, unknown> = {};
  let any = false;
  for (const r of roles) {
    const g = cfg.map[r];
    if (!g) continue;
    any = true;
    for (const s of g.scopes) scopes.add(s);
    claims = { ...claims, ...g.claims };
  }
  if (!any) return null;
  return { scopes: [...scopes], ...(Object.keys(claims).length ? { claims } : {}) };
}

// ---------------------------------------------------------------------------
// Mint audit log — append-only JSONL, never consulted at verify time
// ---------------------------------------------------------------------------

export interface MintRecord {
  at: string;
  jti?: string;
  sub: string;
  aud: string;
  scopes: string[];
  exp: number;
  by: 'oauth' | 'google' | 'password' | 'passkey' | 'setup' | 'exchange' | 'enroll' | 'cli';
}

export class MintLog {
  constructor(private readonly path: string) {}

  append(rec: MintRecord): void {
    try {
      mkdirSync(dirname(this.path), { recursive: true });
      appendFileSync(this.path, JSON.stringify(rec) + '\n');
    } catch (err) {
      console.error(`[hn] mint log write failed: ${(err as Error).message}`);
    }
  }
}
