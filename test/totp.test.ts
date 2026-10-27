import { test } from 'node:test';
import assert from 'node:assert/strict';
import { base32Decode, base32Encode, hotp, totpUri, verifyTotp } from '../src/totp.js';
import { qrMatrix, qrSvg } from '../src/qr.js';

// RFC 6238 Appendix B (SHA-1 seed), truncated to 6 digits.
const SEED = base32Encode(Buffer.from('12345678901234567890'));
const VECTORS: Array<[number, string]> = [
  [59, '287082'], [1111111109, '081804'], [1111111111, '050471'], [1234567890, '005924'], [2000000000, '279037'],
];

test('base32 round-trips', () => {
  for (const n of [0, 1, 5, 10, 20, 33]) {
    const b = Buffer.from(Array.from({ length: n }, (_, i) => (i * 37 + 11) & 0xff));
    assert.deepEqual(base32Decode(base32Encode(b)), b);
  }
  assert.equal(base32Decode('not base32!'), null);
});

test('RFC 6238 vectors', () => {
  for (const [t, code] of VECTORS) {
    assert.equal(hotp(base32Decode(SEED)!, Math.floor(t / 30)), code, `t=${t}`);
    assert.equal(verifyTotp(SEED, code, { nowMs: t * 1000 }), Math.floor(t / 30));
  }
});

test('±1 step drift accepted, further refused; replay refused via lastStep', () => {
  const t = 1111111109 * 1000;
  const step = Math.floor(t / 30_000);
  assert.equal(verifyTotp(SEED, '081804', { nowMs: t + 30_000 }), step); // one step late
  assert.equal(verifyTotp(SEED, '081804', { nowMs: t + 90_000 }), null); // three steps late
  assert.equal(verifyTotp(SEED, '081804', { nowMs: t, lastStep: step }), null); // already used
  assert.equal(verifyTotp(SEED, '08 18 04', { nowMs: t }), step); // spaces tolerated
  assert.equal(verifyTotp(SEED, '81804', { nowMs: t }), null);
});

test('otpauth URI carries issuer, label, secret', () => {
  const u = new URL(totpUri('JBSWY3DPEHPK3PXP', 'alice', 'id.test'));
  assert.equal(u.protocol, 'otpauth:');
  assert.equal(u.host, 'totp');
  assert.equal(decodeURIComponent(u.pathname), '/id.test:alice');
  assert.equal(u.searchParams.get('secret'), 'JBSWY3DPEHPK3PXP');
  assert.equal(u.searchParams.get('issuer'), 'id.test');
});

test('QR: version grows with payload, finder patterns in place, SVG renders', () => {
  // (full decode round-trips over versions 1–40 were checked against jsQR
  //  when this encoder was written; here, structure only)
  const small = qrMatrix('hi');
  assert.equal(small.length, 21); // version 1
  const uri = totpUri('JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP', 'someone.long-name', 'id.animalabs.ai');
  const m = qrMatrix(uri);
  assert.ok(m.length > 21 && (m.length - 17) % 4 === 0);
  for (const [x, y] of [[0, 0], [m.length - 7, 0], [0, m.length - 7]]) {
    assert.equal(m[y]![x], true);
    assert.equal(m[y + 1]![x + 1], false);
    assert.equal(m[y + 3]![x + 3], true);
  }
  assert.match(qrSvg(uri), /^<svg [^>]*viewBox="0 0 \d+ \d+"/);
});
