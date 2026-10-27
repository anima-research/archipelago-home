/**
 * TOTP (RFC 6238: HMAC-SHA1, 30 s step, 6 digits) — the "regular 2FA" every
 * authenticator app speaks. No dependencies; the secret is base32 because
 * that is what `otpauth://` URIs and manual-entry fields expect.
 */
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const TOTP_PERIOD_S = 30;
const DIGITS = 6;

export function base32Encode(buf: Buffer): string {
  let out = '';
  let bits = 0;
  let value = 0;
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string): Buffer | null {
  const clean = s.toUpperCase().replace(/[\s=-]/g, '');
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    const i = B32.indexOf(ch);
    if (i < 0) return null;
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** 160-bit secret (RFC 4226's recommended length), base32. */
export function newTotpSecret(): string {
  return base32Encode(randomBytes(20));
}

export function hotp(secret: Buffer, counter: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = createHmac('sha1', secret).update(msg).digest();
  const off = h[h.length - 1]! & 0x0f;
  const bin = ((h[off]! & 0x7f) << 24) | (h[off + 1]! << 16) | (h[off + 2]! << 8) | h[off + 3]!;
  return String(bin % 10 ** DIGITS).padStart(DIGITS, '0');
}

export function totpStep(nowMs = Date.now()): number {
  return Math.floor(nowMs / 1000 / TOTP_PERIOD_S);
}

/**
 * Check a 6-digit code against the current step ±`window` (clock drift).
 * Returns the matched step so the caller can store it: a step at or below
 * `lastStep` is refused, which makes every code single-use (RFC 6238 §5.2).
 */
export function verifyTotp(
  secretB32: string,
  code: string,
  opts: { nowMs?: number; lastStep?: number; window?: number } = {},
): number | null {
  const c = code.replace(/\s/g, '');
  if (!/^\d{6}$/.test(c)) return null;
  const secret = base32Decode(secretB32);
  if (!secret || !secret.length) return null;
  const now = totpStep(opts.nowMs);
  const w = opts.window ?? 1;
  let matched: number | null = null;
  // Check every candidate (no early exit) so timing doesn't reveal which matched.
  for (let step = now - w; step <= now + w; step++) {
    const ok = timingSafeEqual(Buffer.from(hotp(secret, step)), Buffer.from(c));
    if (ok && (opts.lastStep === undefined || step > opts.lastStep) && matched === null) matched = step;
  }
  return matched;
}

/** The provisioning URI authenticator apps import (Key Uri Format). */
export function totpUri(secretB32: string, account: string, issuer: string): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const q = new URLSearchParams({ secret: secretB32, issuer, algorithm: 'SHA1', digits: String(DIGITS), period: String(TOTP_PERIOD_S) });
  return `otpauth://totp/${label}?${q.toString()}`;
}
