/**
 * The aid1 identity token — the one credential every audience accepts
 * (docs/home-node.md §2). Deliberately not JWT (archipelago rule 5: one
 * algorithm, no negotiation, no JOSE):
 *
 *   aid1.<base64url(payload-json)>.<base64url(ed25519 sig)>
 *
 * The signature covers the LITERAL bytes of `aid1.<payload-segment>` —
 * verifiers check the bytes they received, then parse. No canonicalization.
 */
import { randomBytes, type KeyObject } from 'node:crypto';
import { b64urlToBuf, fingerprintToRaw, signBytes, verifyBytes } from './keys.js';

export const TOKEN_PREFIX = 'aid1';

export type PrincipalKind = 'human' | 'agent' | 'service';

export interface Aid1Payload {
  v: 1;
  /** Issuer domain — the trust anchor (e.g. `id.animalabs.ai`). */
  iss: string;
  /** Durable principal id: `human:discord:<snowflake>` / `agent:<name>@<domain>`. */
  sub: string;
  kind: PrincipalKind;
  /** Display name — uniqueness enforced at enrollment, not here. */
  name: string;
  /** Audience id; verifiers MUST check it equals themselves. */
  aud: string;
  scopes: string[];
  /** Coarse entitlement (e.g. { tier: "sonnet-event" }); never balances. */
  claims?: Record<string, unknown>;
  /** Unix seconds. */
  iat: number;
  exp: number;
  /** Replay guard for single-use login-redirect tokens. */
  jti?: string;
}

export function mintToken(privateKey: KeyObject, payload: Aid1Payload): string {
  const seg = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signed = `${TOKEN_PREFIX}.${seg}`;
  const sig = signBytes(privateKey, Buffer.from(signed, 'utf8'));
  return `${signed}.${sig.toString('base64url')}`;
}

export function newJti(): string {
  return randomBytes(12).toString('base64url');
}

export type VerifyOutcome =
  | { ok: true; payload: Aid1Payload }
  | { ok: false; reason: string };

export interface VerifyOpts {
  /** Issuer public key fingerprint `ed25519:<b64url raw 32B>`. */
  issuerId: string;
  /** Expected `iss` domain. */
  iss: string;
  /** This service's audience id. */
  aud: string;
  /** Scopes that must ALL be present. */
  requireScopes?: string[];
  /** Override clock (unix ms) for tests. */
  nowMs?: number;
}

/**
 * Pure offline verification — the whole audience contract of
 * docs/home-node.md §5 steps 1–3. Returns a reason string on failure so
 * callers can log it (headless-box diagnosability, per the observer layer).
 */
export function verifyToken(token: string, opts: VerifyOpts): VerifyOutcome {
  const fail = (reason: string): VerifyOutcome => ({ ok: false, reason });
  if (typeof token !== 'string') return fail('not a string');
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== TOKEN_PREFIX) return fail('not an aid1 token');
  const [, seg, sigSeg] = parts as [string, string, string];

  const rawKey = fingerprintToRaw(opts.issuerId);
  if (!rawKey) return fail('malformed issuer key');
  const sig = b64urlToBuf(sigSeg);
  if (!sig || sig.length !== 64) return fail('malformed signature');
  if (!verifyBytes(rawKey, Buffer.from(`${TOKEN_PREFIX}.${seg}`, 'utf8'), sig)) {
    return fail('signature verify failed');
  }

  const segBuf = b64urlToBuf(seg);
  if (!segBuf) return fail('malformed payload segment');
  let payload: Aid1Payload;
  try {
    payload = JSON.parse(segBuf.toString('utf8')) as Aid1Payload;
  } catch {
    return fail('payload not JSON');
  }
  if (payload.v !== 1) return fail(`unsupported version ${String((payload as { v?: unknown }).v)}`);
  if (payload.iss !== opts.iss) return fail(`issuer mismatch (${payload.iss})`);
  if (payload.aud !== opts.aud) return fail(`audience mismatch (${payload.aud})`);
  if (typeof payload.sub !== 'string' || !payload.sub) return fail('missing sub');
  if (typeof payload.name !== 'string' || !payload.name) return fail('missing name');
  if (!Array.isArray(payload.scopes) || !payload.scopes.every((s) => typeof s === 'string')) {
    return fail('malformed scopes');
  }
  const now = (opts.nowMs ?? Date.now()) / 1000;
  if (typeof payload.exp !== 'number' || payload.exp <= now) return fail('expired');
  if (typeof payload.iat !== 'number' || payload.iat > now + 300) return fail('iat in the future');
  for (const s of opts.requireScopes ?? []) {
    if (!payload.scopes.includes(s)) return fail(`missing scope ${s}`);
  }
  return { ok: true, payload };
}

/**
 * Single-use guard for login-redirect tokens (§8): in-memory seen-set with
 * expiry-based eviction. A restart forgetting the set is covered by the
 * token's own 10-minute exp.
 */
export class JtiCache {
  private seen = new Map<string, number>(); // jti → exp unix-seconds

  /** Returns true when the jti is fresh (and records it); false on replay. */
  claim(jti: string, expUnixSec: number, nowMs = Date.now()): boolean {
    const now = nowMs / 1000;
    for (const [k, exp] of this.seen) if (exp <= now) this.seen.delete(k);
    if (this.seen.has(jti)) return false;
    this.seen.set(jti, expUnixSec);
    return true;
  }
}

/** Parse `10m` / `72h` / `14d` into milliseconds. Throws on malformation. */
export function parseTtl(ttl: string): number {
  const m = /^(\d+)([mhd])$/.exec(ttl);
  if (!m) throw new Error(`bad ttl "${ttl}" — expected e.g. 30m, 72h, 14d`);
  const n = Number(m[1]);
  return n * { m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2] as 'm' | 'h' | 'd'];
}
