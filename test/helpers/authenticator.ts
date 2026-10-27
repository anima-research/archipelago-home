/**
 * A software WebAuthn authenticator for tests: makes `none`-attestation
 * credentials and signs assertions exactly as a platform authenticator
 * would, so the relying-party checks run against real bytes.
 */
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';

// minimal CBOR encoder (what attestation objects / COSE keys use)
function head(major: number, n: number): Buffer {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(n, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(n, 1);
  return b;
}
export function cbor(v: unknown): Buffer {
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === 'string') {
    const s = Buffer.from(v, 'utf8');
    return Buffer.concat([head(3, s.length), s]);
  }
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  if (v instanceof Map) {
    const parts: Buffer[] = [head(5, v.size)];
    for (const [k, val] of v) parts.push(cbor(k), cbor(val));
    return Buffer.concat(parts);
  }
  throw new Error(`cbor: can't encode ${typeof v}`);
}

const b64u = (b: Buffer) => b.toString('base64url');

export class SoftAuthenticator {
  readonly credentialId = randomBytes(16);
  private priv: KeyObject;
  private cose: Map<number, unknown>;
  signCount = 0;
  userHandle: string | null = null;
  /** Flags to put in authData (UP|UV by default). */
  flags = 0x05;
  constructor(readonly alg: -7 | -8 | -257, readonly origin: string, readonly rpId: string, opts: { counting?: boolean } = {}) {
    this.counting = opts.counting ?? false;
    if (alg === -257) {
      const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
      const jwk = publicKey.export({ format: 'jwk' });
      this.priv = privateKey;
      this.cose = new Map<number, unknown>([[1, 3], [3, -257], [-1, Buffer.from(jwk.n!, 'base64url')], [-2, Buffer.from(jwk.e!, 'base64url')]]);
    } else if (alg === -7) {
      const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const jwk = publicKey.export({ format: 'jwk' });
      this.priv = privateKey;
      this.cose = new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, 'base64url')], [-3, Buffer.from(jwk.y!, 'base64url')]]);
    } else {
      const { privateKey, publicKey } = generateKeyPairSync('ed25519');
      const jwk = publicKey.export({ format: 'jwk' });
      this.priv = privateKey;
      this.cose = new Map<number, unknown>([[1, 1], [3, -8], [-1, 6], [-2, Buffer.from(jwk.x!, 'base64url')]]);
    }
  }
  private counting: boolean;

  private authData(attested: boolean, rpId = this.rpId): Buffer {
    const count = Buffer.alloc(4);
    if (this.counting) this.signCount += 1;
    count.writeUInt32BE(this.signCount);
    const parts = [createHash('sha256').update(rpId).digest(), Buffer.from([this.flags | (attested ? 0x40 : 0)]), count];
    if (attested) {
      const len = Buffer.alloc(2);
      len.writeUInt16BE(this.credentialId.length);
      parts.push(Buffer.alloc(16), len, this.credentialId, cbor(this.cose));
    }
    return Buffer.concat(parts);
  }

  private clientData(type: string, challenge: string, origin = this.origin): Buffer {
    return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  }

  /** navigator.credentials.create(), as the page posts it. */
  create(opts: { challenge: string; user: { id: string } }, override: { origin?: string; rpId?: string } = {}) {
    this.userHandle = opts.user.id;
    const attestationObject = cbor(new Map<string, unknown>([['fmt', 'none'], ['attStmt', new Map()], ['authData', this.authData(true, override.rpId)]]));
    return {
      id: b64u(this.credentialId),
      type: 'public-key',
      response: { clientDataJSON: b64u(this.clientData('webauthn.create', opts.challenge, override.origin)), attestationObject: b64u(attestationObject) },
    };
  }

  /** navigator.credentials.get(). */
  get(opts: { challenge: string }, override: { origin?: string; rpId?: string } = {}) {
    const ad = this.authData(false, override.rpId);
    const cd = this.clientData('webauthn.get', opts.challenge, override.origin);
    const signed = Buffer.concat([ad, createHash('sha256').update(cd).digest()]);
    const signature =
      this.alg === -7 ? sign('sha256', signed, { key: this.priv, dsaEncoding: 'der' })
        : this.alg === -257 ? sign('sha256', signed, this.priv) // RSASSA-PKCS1-v1_5
          : sign(null, signed, this.priv);
    return {
      id: b64u(this.credentialId),
      type: 'public-key',
      response: {
        clientDataJSON: b64u(cd),
        authenticatorData: b64u(ad),
        signature: b64u(signature),
        userHandle: this.userHandle,
      },
    };
  }
}
