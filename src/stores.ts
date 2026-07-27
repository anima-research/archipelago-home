/**
 * Hot-reloaded JSON stores — the thrice-proven pattern (discord-mcpl
 * filters → fkm observers → portal): atomic tmp+rename writes, mtime poll,
 * parse-error-keeps-previous. Plus the append-only mint audit log.
 */
import {
  appendFileSync,
  mkdirSync,
  readFileSync,
  renameSync,
  statSync,
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

  get(): T {
    return this.value;
  }

  /** Atomic write-through (tmp+rename); pollers never see a half-write. */
  set(next: T): void {
    this.value = next;
    mkdirSync(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(next, null, 2) + '\n');
    renameSync(tmp, this.path);
    try {
      this.lastMtime = statSync(this.path).mtimeMs; // suppress self-reload
    } catch {
      /* ignore */
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
}

export type AudiencesConfig = Record<string, AudienceConfig>;

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
  by: 'oauth' | 'exchange' | 'enroll' | 'cli';
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
