/**
 * Passkeys — the relying-party half of WebAuthn Level 2, for `attestation:
 * "none"` (we trust the account holder registering their own authenticator;
 * we don't need the authenticator's make vouched for). No dependencies: a
 * bounded CBOR reader, COSE → JWK for the three algorithms every platform
 * authenticator uses (EdDSA, ES256, RS256), and the §7.1 / §7.2 checks.
 *
 * User verification is REQUIRED on both ceremonies: a passkey login stands
 * in for password + second factor, so the authenticator must have checked
 * the person (biometric / device PIN), not just presence.
 */
import { createHash, createPublicKey, timingSafeEqual, verify as cryptoVerify, type JsonWebKey } from 'node:crypto';

export const COSE_ALGS = [-8, -7, -257] as const; // EdDSA, ES256, RS256 — preference order

// ── CBOR (RFC 8949), the subset authenticators emit ──

const MAX_DEPTH = 16;

export function cborDecode(buf: Buffer, offset = 0, depth = 0): { value: unknown; end: number } {
  if (depth > MAX_DEPTH) throw new Error('cbor: too deep');
  const need = (n: number) => {
    if (offset + n > buf.length) throw new Error('cbor: truncated');
  };
  need(1);
  const ib = buf[offset++]!;
  const major = ib >> 5;
  const info = ib & 0x1f;
  let arg: number;
  if (info < 24) arg = info;
  else if (info === 24) (need(1), (arg = buf.readUInt8(offset)), (offset += 1));
  else if (info === 25) (need(2), (arg = buf.readUInt16BE(offset)), (offset += 2));
  else if (info === 26) (need(4), (arg = buf.readUInt32BE(offset)), (offset += 4));
  else if (info === 27) {
    need(8);
    const big = buf.readBigUInt64BE(offset);
    offset += 8;
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('cbor: integer too large');
    arg = Number(big);
  } else throw new Error('cbor: indefinite lengths unsupported');

  switch (major) {
    case 0:
      return { value: arg, end: offset };
    case 1:
      return { value: -1 - arg, end: offset };
    case 2:
      need(arg);
      return { value: Buffer.from(buf.subarray(offset, offset + arg)), end: offset + arg };
    case 3:
      need(arg);
      return { value: buf.toString('utf8', offset, offset + arg), end: offset + arg };
    case 4: {
      if (arg > buf.length) throw new Error('cbor: bad array length');
      const arr: unknown[] = [];
      for (let i = 0; i < arg; i++) {
        const r = cborDecode(buf, offset, depth + 1);
        arr.push(r.value);
        offset = r.end;
      }
      return { value: arr, end: offset };
    }
    case 5: {
      if (arg > buf.length) throw new Error('cbor: bad map length');
      const map = new Map<unknown, unknown>();
      for (let i = 0; i < arg; i++) {
        const k = cborDecode(buf, offset, depth + 1);
        const v = cborDecode(buf, k.end, depth + 1);
        map.set(k.value, v.value);
        offset = v.end;
      }
      return { value: map, end: offset };
    }
    case 6:
      return cborDecode(buf, offset, depth + 1); // tag: ignore, keep the content
    default: // 7: simple values / floats
      if (info === 20) return { value: false, end: offset };
      if (info === 21) return { value: true, end: offset };
      if (info === 22 || info === 23) return { value: null, end: offset };
      if (info === 25) return { value: halfToFloat(arg), end: offset };
      if (info === 26) return { value: buf.readFloatBE(offset - 4), end: offset };
      if (info === 27) return { value: buf.readDoubleBE(offset - 8), end: offset };
      throw new Error('cbor: unsupported simple value');
  }
}

function halfToFloat(h: number): number {
  const s = h & 0x8000 ? -1 : 1;
  const e = (h >> 10) & 0x1f;
  const f = h & 0x3ff;
  if (e === 0) return s * 2 ** -14 * (f / 1024);
  if (e === 31) return f ? NaN : s * Infinity;
  return s * 2 ** (e - 15) * (1 + f / 1024);
}

// ── authenticator data (§6.1) ──

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;

export interface AuthData {
  rpIdHash: Buffer;
  flags: number;
  signCount: number;
  credentialId?: Buffer;
  cosePublicKey?: Map<unknown, unknown>;
}

export function parseAuthData(buf: Buffer): AuthData {
  if (buf.length < 37) throw new Error('authData too short');
  const out: AuthData = { rpIdHash: buf.subarray(0, 32), flags: buf[32]!, signCount: buf.readUInt32BE(33) };
  if (out.flags & FLAG_AT) {
    if (buf.length < 55) throw new Error('attested credential data truncated');
    const idLen = buf.readUInt16BE(53);
    if (idLen > 1023 || 55 + idLen > buf.length) throw new Error('bad credential id length');
    out.credentialId = Buffer.from(buf.subarray(55, 55 + idLen));
    const key = cborDecode(buf, 55 + idLen);
    if (!(key.value instanceof Map)) throw new Error('credential public key is not a COSE map');
    out.cosePublicKey = key.value;
  }
  return out;
}

// ── COSE_Key → JWK ──

export function coseToJwk(cose: Map<unknown, unknown>): { jwk: JsonWebKey; alg: number } {
  const kty = cose.get(1);
  const alg = cose.get(3);
  const b = (label: number) => {
    const v = cose.get(label);
    if (!Buffer.isBuffer(v)) throw new Error(`COSE key: missing ${label}`);
    return v.toString('base64url');
  };
  let jwk: JsonWebKey;
  if (kty === 1 && alg === -8 && cose.get(-1) === 6) jwk = { kty: 'OKP', crv: 'Ed25519', x: b(-2) };
  else if (kty === 2 && alg === -7 && cose.get(-1) === 1) jwk = { kty: 'EC', crv: 'P-256', x: b(-2), y: b(-3) };
  else if (kty === 3 && alg === -257) jwk = { kty: 'RSA', n: b(-1), e: b(-2) };
  else throw new Error(`unsupported credential key (kty ${String(kty)}, alg ${String(alg)})`);
  createPublicKey({ key: jwk, format: 'jwk' }); // throws on an off-curve / malformed key
  return { jwk, alg: alg as number };
}

// ── ceremonies ──

export interface RelyingParty {
  /** e.g. `id.animalabs.ai` — the public URL's hostname. */
  rpId: string;
  /** e.g. `https://id.animalabs.ai` — exact origin the browser reports. */
  origin: string;
}

export type WebAuthnResult<T> = ({ ok: true } & T) | { ok: false; reason: string };

interface ClientData {
  type?: unknown;
  challenge?: unknown;
  origin?: unknown;
  crossOrigin?: unknown;
}

function b64(s: unknown): Buffer | null {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*={0,2}$/.test(s)) return null;
  return Buffer.from(s, 'base64url');
}

/** The challenge a response claims to answer — the caller looks up its
 *  pending ceremony by this, then verifies against what it stored. */
export function clientDataChallenge(clientDataJSON: unknown): string | null {
  const raw = b64(clientDataJSON);
  if (!raw) return null;
  try {
    const c = JSON.parse(raw.toString('utf8')) as ClientData;
    return typeof c.challenge === 'string' ? c.challenge : null;
  } catch {
    return null;
  }
}

function checkClientData(raw: Buffer, type: string, challenge: string, rp: RelyingParty): string | null {
  let c: ClientData;
  try {
    c = JSON.parse(raw.toString('utf8')) as ClientData;
  } catch {
    return 'clientDataJSON is not JSON';
  }
  if (c.type !== type) return `clientData type ${String(c.type)}`;
  if (typeof c.challenge !== 'string' || !safeEq(c.challenge, challenge)) return 'challenge mismatch';
  if (c.origin !== rp.origin) return `origin mismatch (${String(c.origin)})`;
  if (c.crossOrigin === true) return 'cross-origin ceremony';
  return null;
}

function checkFlags(auth: AuthData, rp: RelyingParty): string | null {
  const want = createHash('sha256').update(rp.rpId).digest();
  if (!timingSafeEqual(auth.rpIdHash, want)) return 'rpId mismatch';
  if (!(auth.flags & FLAG_UP)) return 'user not present';
  if (!(auth.flags & FLAG_UV)) return 'user not verified (passkeys here require biometric / device PIN)';
  return null;
}

/** §7.1 — registration. Returns what to store. */
export function verifyRegistration(
  resp: { id?: unknown; response?: { clientDataJSON?: unknown; attestationObject?: unknown } },
  challenge: string,
  rp: RelyingParty,
): WebAuthnResult<{ credentialId: string; jwk: JsonWebKey; alg: number; signCount: number }> {
  try {
    const cdj = b64(resp.response?.clientDataJSON);
    const att = b64(resp.response?.attestationObject);
    if (!cdj || !att) return { ok: false, reason: 'malformed response' };
    const bad = checkClientData(cdj, 'webauthn.create', challenge, rp);
    if (bad) return { ok: false, reason: bad };
    const obj = cborDecode(att).value;
    if (!(obj instanceof Map) || !Buffer.isBuffer(obj.get('authData'))) return { ok: false, reason: 'malformed attestation object' };
    const auth = parseAuthData(obj.get('authData') as Buffer);
    const flagErr = checkFlags(auth, rp);
    if (flagErr) return { ok: false, reason: flagErr };
    if (!auth.credentialId || !auth.cosePublicKey) return { ok: false, reason: 'no attested credential' };
    const credentialId = auth.credentialId.toString('base64url');
    if (typeof resp.id === 'string' && resp.id !== credentialId) return { ok: false, reason: 'credential id mismatch' };
    const { jwk, alg } = coseToJwk(auth.cosePublicKey);
    return { ok: true, credentialId, jwk, alg, signCount: auth.signCount };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

/** §7.2 — authentication, against a stored credential. */
export function verifyAssertion(
  resp: { response?: { clientDataJSON?: unknown; authenticatorData?: unknown; signature?: unknown } },
  challenge: string,
  rp: RelyingParty,
  cred: { jwk: JsonWebKey; alg: number; signCount: number },
): WebAuthnResult<{ signCount: number }> {
  try {
    const cdj = b64(resp.response?.clientDataJSON);
    const ad = b64(resp.response?.authenticatorData);
    const sig = b64(resp.response?.signature);
    if (!cdj || !ad || !sig) return { ok: false, reason: 'malformed response' };
    const bad = checkClientData(cdj, 'webauthn.get', challenge, rp);
    if (bad) return { ok: false, reason: bad };
    const auth = parseAuthData(ad);
    const flagErr = checkFlags(auth, rp);
    if (flagErr) return { ok: false, reason: flagErr };
    const signed = Buffer.concat([ad, createHash('sha256').update(cdj).digest()]);
    const key = createPublicKey({ key: cred.jwk, format: 'jwk' });
    const ok =
      cred.alg === -8
        ? cryptoVerify(null, signed, key, sig)
        : cred.alg === -7
          ? cryptoVerify('sha256', signed, { key, dsaEncoding: 'der' }, sig)
          : cred.alg === -257
            ? cryptoVerify('sha256', signed, key, sig)
            : false;
    if (!ok) return { ok: false, reason: 'signature verify failed' };
    // Synced passkeys report 0 forever; a counter that is in use must climb.
    if ((auth.signCount !== 0 || cred.signCount !== 0) && auth.signCount <= cred.signCount) {
      return { ok: false, reason: 'signature counter went backwards (cloned authenticator?)' };
    }
    return { ok: true, signCount: auth.signCount };
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
}

function safeEq(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
