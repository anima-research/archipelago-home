/**
 * ed25519 key material — issuer key load/create + raw↔KeyObject helpers.
 * Cribbed from fleet-watch src/keys.ts and fkm web-ui-observers.ts (the
 * shipped observer-identity layer); same fingerprint format:
 *
 *   ed25519:<base64url of the raw 32-byte public key>
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto';

export interface IssuerKey {
  privateKey: KeyObject;
  /** `ed25519:<base64url raw 32-byte public key>` */
  id: string;
}

/** DER prefix that wraps a raw 32-byte ed25519 public key into SPKI. */
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export function rawToPublicKey(raw: Buffer): KeyObject {
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}

export function fingerprintOfPrivate(privateKey: KeyObject): string {
  const spki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' }) as Buffer;
  return `ed25519:${spki.subarray(spki.length - 32).toString('base64url')}`;
}

/** `ed25519:<b64url>` → raw 32-byte buffer, or null on any malformation. */
export function fingerprintToRaw(id: string): Buffer | null {
  if (typeof id !== 'string' || !id.startsWith('ed25519:')) return null;
  const raw = b64urlToBuf(id.slice('ed25519:'.length));
  return raw && raw.length === 32 ? raw : null;
}

export function b64urlToBuf(s: string): Buffer | null {
  try {
    if (typeof s !== 'string' || /[^A-Za-z0-9_-]/.test(s)) return null;
    return Buffer.from(s, 'base64url');
  } catch {
    return null;
  }
}

export function loadOrCreateIssuerKey(pemPath: string): IssuerKey {
  let privateKey: KeyObject;
  if (existsSync(pemPath)) {
    privateKey = createPrivateKey(readFileSync(pemPath, 'utf8'));
  } else {
    const pair = generateKeyPairSync('ed25519');
    privateKey = pair.privateKey;
    mkdirSync(dirname(pemPath), { recursive: true });
    writeFileSync(pemPath, privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
  }
  return { privateKey, id: fingerprintOfPrivate(privateKey) };
}

/** Generate an in-memory keypair (client-side enrollment, tests). */
export function generateKey(): IssuerKey {
  const pair = generateKeyPairSync('ed25519');
  return { privateKey: pair.privateKey, id: fingerprintOfPrivate(pair.privateKey) };
}

export function signBytes(privateKey: KeyObject, bytes: Buffer): Buffer {
  return cryptoSign(null, bytes, privateKey);
}

/** Verify sig over bytes with a raw 32-byte public key. Never throws. */
export function verifyBytes(rawPublicKey: Buffer, bytes: Buffer, sig: Buffer): boolean {
  try {
    return cryptoVerify(null, bytes, rawToPublicKey(rawPublicKey), sig);
  } catch {
    return false;
  }
}
