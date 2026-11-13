/**
 * Access codes for people: a code the operator hands out (`hn code add`)
 * that grants named AUDIENCES — and the scopes those audiences need — to
 * whoever redeems it, on the sign-in page (which also lets a newcomer sign
 * up through Google or Discord) or later under sign-in settings.
 *
 * What a code grants counts ONLY for its own audiences. It never widens what
 * a person holds anywhere else: several audiences have no requiredScopes and
 * admit anyone holding any grant at all, and a code for one service must not
 * open those.
 *
 * Access is resolved live from this file: an account keeps only which codes
 * it redeemed, so `hn code revoke` takes the access away from everyone who
 * used the code, and `hn code close` just stops new redemptions. `expires`
 * and `maxUses` limit redeeming, not the access once redeemed.
 *
 * The file keeps a hash of each code, never the code (0600 anyway): it is
 * shown once, when made.
 */
import { randomBytes } from 'node:crypto';
import { JsonStore, type RoleGrant } from './stores.js';
import { sha256hex } from './accounts.js';

export interface AccessCode {
  /** Public handle: what accounts, logs and the CLI refer to. */
  id: string;
  /** sha256 (hex) of the normalized code. */
  hash: string;
  label: string;
  audiences: string[];
  /** Stamped into tokens for those audiences (their requiredScopes, and any extra). */
  scopes: string[];
  claims?: Record<string, unknown>;
  maxUses?: number;
  uses: number;
  /** Last moment it can be redeemed (ISO). */
  expires?: string;
  /** No new redemptions; what it gave stays. */
  closed?: boolean;
  /** What it gave is gone, for everyone. */
  revoked?: boolean;
  createdAt: string;
  redeemed: Array<{ sub: string; at: string }>;
}

export interface CodesFile {
  codes: AccessCode[];
}

export type CodeRejection = 'unknown' | 'expired' | 'used up' | 'closed';

function validateCodes(raw: unknown): CodesFile | null {
  const f = raw as CodesFile;
  if (!f || !Array.isArray(f.codes)) return null;
  const ids = new Set<string>();
  for (const c of f.codes) {
    if (typeof c.id !== 'string' || typeof c.hash !== 'string' || ids.has(c.id)) return null;
    if (!Array.isArray(c.audiences) || !Array.isArray(c.scopes) || !Array.isArray(c.redeemed)) return null;
    ids.add(c.id);
  }
  return f;
}

const ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789'; // no 0/o/1/l/i

/** `xxxx-xxxx-xxxx`: ~59 bits, so guessing is hopeless behind the rate limit. */
export function newCodeText(): string {
  const b = randomBytes(12);
  const s = [...b].map((x) => ALPHABET[x % ALPHABET.length]).join('');
  return `${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8)}`;
}

export function normalizeCode(code: string): string {
  return code.toLowerCase().replace(/[^a-z0-9]/g, '');
}

export class CodeStore {
  private store: JsonStore<CodesFile>;

  constructor(path: string) {
    this.store = new JsonStore(path, validateCodes, { codes: [] }, 'codes', 0o600);
  }
  startWatching(): void {
    this.store.startWatching();
  }
  stopWatching(): void {
    this.store.stopWatching();
  }

  all(): AccessCode[] {
    this.store.refresh();
    return this.store.get().codes;
  }
  byId(id: string): AccessCode | undefined {
    return this.all().find((c) => c.id === id);
  }

  /** The code if it can be redeemed now, else why not. Reads only. */
  check(code: string, nowMs = Date.now()): AccessCode | CodeRejection {
    const n = normalizeCode(code);
    if (n.length < 8) return 'unknown';
    const h = sha256hex(n);
    const c = this.all().find((x) => x.hash === h);
    return c ? usable(c, nowMs) : 'unknown';
  }

  /**
   * Redeem for `sub`, under the store lock: counts a use the first time this
   * sub redeems it; redeeming again is a no-op that still succeeds.
   */
  redeem(code: string, sub: string, nowMs = Date.now()): AccessCode | CodeRejection {
    const h = sha256hex(normalizeCode(code));
    let out: AccessCode | CodeRejection = 'unknown';
    this.store.update((f) => {
      const c = f.codes.find((x) => x.hash === h);
      if (!c) return f;
      if (c.redeemed.some((r) => r.sub === sub) && !c.revoked) {
        out = c;
        return f;
      }
      const u = usable(c, nowMs);
      if (typeof u === 'string') {
        out = u;
        return f;
      }
      const next: AccessCode = { ...c, uses: c.uses + 1, redeemed: [...c.redeemed, { sub, at: new Date(nowMs).toISOString() }] };
      out = next;
      return { codes: f.codes.map((x) => (x.id === c.id ? next : x)) };
    });
    return out;
  }

  add(c: Omit<AccessCode, 'id' | 'hash' | 'uses' | 'redeemed' | 'createdAt'>, nowMs = Date.now()): { code: string; record: AccessCode } {
    const code = newCodeText();
    const record: AccessCode = {
      id: `code_${randomBytes(4).toString('hex')}`,
      hash: sha256hex(normalizeCode(code)),
      ...c,
      uses: 0,
      createdAt: new Date(nowMs).toISOString(),
      redeemed: [],
    };
    this.store.update((f) => ({ codes: [...f.codes, record] }));
    return { code, record };
  }

  set(id: string, patch: Partial<Pick<AccessCode, 'closed' | 'revoked'>>): AccessCode | undefined {
    let out: AccessCode | undefined;
    this.store.update((f) => {
      const c = f.codes.find((x) => x.id === id);
      if (!c) return f;
      out = { ...c, ...patch };
      return { codes: f.codes.map((x) => (x.id === id ? out! : x)) };
    });
    return out;
  }

  /** What the codes an account redeemed grant for this one audience (null = nothing). */
  grantFor(redeemed: Array<{ id: string }> | undefined, audience: string): RoleGrant | null {
    if (!redeemed?.length) return null;
    const scopes = new Set<string>();
    let claims: Record<string, unknown> = {};
    let any = false;
    for (const r of redeemed) {
      const c = this.byId(r.id);
      if (!c || c.revoked || !c.audiences.includes(audience)) continue;
      any = true;
      for (const s of c.scopes) scopes.add(s);
      claims = { ...claims, ...c.claims };
    }
    if (!any) return null;
    return { scopes: [...scopes], ...(Object.keys(claims).length ? { claims } : {}) };
  }
}

function usable(c: AccessCode, nowMs: number): AccessCode | CodeRejection {
  if (c.revoked || c.closed) return 'closed';
  if (c.expires && Date.parse(c.expires) <= nowMs) return 'expired';
  if (c.maxUses !== undefined && c.uses >= c.maxUses) return 'used up';
  return c;
}

export function rejectionText(r: CodeRejection): string {
  switch (r) {
    case 'unknown':
      return 'that code isn’t valid — check it and try again';
    case 'expired':
      return 'that code has expired — ask for a new one';
    case 'used up':
      return 'that code has been used up — ask for a new one';
    case 'closed':
      return 'that code is no longer accepted — ask for a new one';
  }
}
