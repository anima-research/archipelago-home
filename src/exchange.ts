/**
 * Pure cores of POST /token and POST /enroll (docs/home-node.md §4) —
 * factored out of the HTTP layer for direct unit testing, in the style of
 * fkm's verifyHello. Every rejection carries a one-line reason; the server
 * logs it (headless-box diagnosability).
 */
import type { IssuerKey } from './keys.js';
import { fingerprintToRaw, b64urlToBuf, verifyBytes } from './keys.js';
import { mintToken, parseTtl, type Aid1Payload } from './token.js';
import {
  FRESHNESS_MS,
  enrollStatement,
  tokenStatement,
  type EnrollRequest,
  type TokenRequest,
} from './statements.js';
import type { InviteStore, MintLog, Principal, PrincipalStore } from './stores.js';

export interface ExchangeDeps {
  issuer: IssuerKey;
  /** Issuer domain (`iss` claim). */
  iss: string;
  principals: PrincipalStore;
  invites: InviteStore;
  mintLog: MintLog;
  /** Known audience ids (from audiences.json) — absent audience = rejected. */
  knownAudiences: () => string[];
  nowMs?: () => number;
}

export type ExchangeResult =
  | { status: 200; body: Record<string, unknown> }
  | { status: 400 | 403; body: { error: string } };

const DEFAULT_AGENT_TTL = '7d';
/** Guests enrolled via invite default to a short leash unless the invite says otherwise. */
const DEFAULT_ENROLL_TTL = '72h';

function checkProof(
  proofSeg: string | undefined,
  keyId: string,
  statement: string,
): string | null {
  const raw = fingerprintToRaw(keyId);
  if (!raw) return 'malformed public key';
  const sig = b64urlToBuf(proofSeg ?? '');
  if (!sig || sig.length !== 64) return 'malformed signature';
  if (!verifyBytes(raw, Buffer.from(statement, 'utf8'), sig)) return 'signature verify failed';
  return null;
}

function checkFreshness(timestamp: string | undefined, nowMs: number): string | null {
  const ts = Date.parse(timestamp ?? '');
  if (!Number.isFinite(ts)) return 'bad timestamp';
  if (Math.abs(nowMs - ts) > FRESHNESS_MS) return 'stale timestamp';
  return null;
}

function mintFor(
  deps: ExchangeDeps,
  p: Principal,
  aud: string,
  by: 'exchange' | 'enroll',
  nowMs: number,
): string {
  const ttlMs = parseTtl(p.tokenTtl ?? DEFAULT_AGENT_TTL);
  const payload: Aid1Payload = {
    v: 1,
    iss: deps.iss,
    sub: p.sub,
    kind: p.kind,
    name: p.name,
    aud,
    scopes: p.scopes,
    ...(p.claims ? { claims: p.claims } : {}),
    iat: Math.floor(nowMs / 1000),
    exp: Math.floor((nowMs + ttlMs) / 1000),
  };
  const token = mintToken(deps.issuer.privateKey, payload);
  deps.mintLog.append({
    at: new Date(nowMs).toISOString(),
    sub: p.sub,
    aud,
    scopes: p.scopes,
    exp: payload.exp,
    by,
  });
  return token;
}

/** POST /token — key-proof → fresh aid1 token for an enrolled principal. */
export function handleTokenRequest(body: unknown, deps: ExchangeDeps): ExchangeResult {
  const nowMs = deps.nowMs?.() ?? Date.now();
  const req = body as TokenRequest;
  const fail = (status: 400 | 403, error: string): ExchangeResult => {
    console.error(`[hn] /token rejected (${req?.id ?? 'no-id'}): ${error}`);
    return { status, body: { error } };
  };
  if (!req || typeof req.id !== 'string' || typeof req.audience !== 'string') {
    return fail(400, 'malformed request');
  }
  const freshErr = checkFreshness(req.timestamp, nowMs);
  if (freshErr) return fail(400, freshErr);
  if (!deps.knownAudiences().includes(req.audience)) return fail(400, 'unknown audience');

  const p = deps.principals.byKey(req.id);
  if (!p) return fail(403, 'no principal for key');
  if (!deps.principals.isLive(p, nowMs)) return fail(403, 'principal expired');
  if (p.audiences && !p.audiences.includes(req.audience)) return fail(403, 'audience not allowed');

  const proofErr = checkProof(req.proof, req.id, tokenStatement(deps.iss, req.audience, req.timestamp));
  if (proofErr) return fail(403, proofErr);

  return { status: 200, body: { token: mintFor(deps, p, req.audience, 'exchange', nowMs), sub: p.sub } };
}

/** POST /enroll — invite + pubkey → new principal + first token. */
export function handleEnroll(body: unknown, deps: ExchangeDeps): ExchangeResult {
  const nowMs = deps.nowMs?.() ?? Date.now();
  const req = body as EnrollRequest;
  const fail = (status: 400 | 403, error: string): ExchangeResult => {
    console.error(`[hn] /enroll rejected (${req?.name ?? 'no-name'}): ${error}`);
    return { status, body: { error } };
  };
  if (!req || typeof req.invite !== 'string' || typeof req.id !== 'string' || typeof req.name !== 'string') {
    return fail(400, 'malformed request');
  }
  if (!/^[a-zA-Z0-9][a-zA-Z0-9 _.-]{0,31}$/.test(req.name)) return fail(400, 'bad name (1-32 chars, alnum/space/_/./-)');
  const freshErr = checkFreshness(req.timestamp, nowMs);
  if (freshErr) return fail(400, freshErr);

  const inv = deps.invites.check(req.invite, nowMs);
  if (typeof inv === 'string') return fail(403, `invite ${inv}`);

  const proofErr = checkProof(req.proof, req.id, enrollStatement(deps.iss, req.invite, req.timestamp));
  if (proofErr) return fail(403, proofErr);

  if (deps.principals.nameTaken(req.name)) return fail(403, 'name taken');
  if (deps.principals.byKey(req.id)) return fail(403, 'key already enrolled');

  // An invite resolves to a NEW principal (archipelago rule 6). The anchor
  // defaults to `guest`; a domain-bearing invite (operator-only) enrolls
  // straight into the home's own namespace.
  const slug = req.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  const p: Principal = {
    sub: `agent:${slug}@${inv.domain ?? 'guest'}`,
    name: req.name,
    kind: 'agent',
    key: req.id,
    scopes: inv.scopes,
    ...(inv.claims ? { claims: inv.claims } : {}),
    ...(inv.audiences ? { audiences: inv.audiences } : {}),
    tokenTtl: inv.tokenTtl ?? DEFAULT_ENROLL_TTL,
    notes: `enrolled via invite ${inv.code}${inv.label ? ` (${inv.label})` : ''}`,
  };
  if (deps.principals.bySub(p.sub)) return fail(403, 'name taken'); // slug collision
  deps.principals.add(p);
  deps.invites.consume(inv.code);
  const aud = inv.audiences?.[0] ?? deps.knownAudiences()[0];
  if (!aud) return fail(400, 'no audience configured');
  return {
    status: 200,
    body: { sub: p.sub, token: mintFor(deps, p, aud, 'enroll', nowMs) },
  };
}
