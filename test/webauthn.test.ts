import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cborDecode, verifyAssertion, verifyRegistration } from '../src/webauthn.js';
import { cbor, SoftAuthenticator } from './helpers/authenticator.js';

const RP = { rpId: 'id.test', origin: 'https://id.test' };
const CH = 'Y2hhbGxlbmdlLWNoYWxsZW5nZS1jaGFsbGVuZ2UtMzI';

for (const alg of [-7, -8, -257] as const) {
  test(`register + assert round trip, forged signature refused (alg ${alg})`, () => {
    const a = new SoftAuthenticator(alg, RP.origin, RP.rpId, { counting: alg === -7 });
    const reg = verifyRegistration(a.create({ challenge: CH, user: { id: 'dXNlcg' } }), CH, RP);
    assert.ok(reg.ok, !reg.ok ? reg.reason : '');
    assert.equal(reg.alg, alg);
    const cred = { jwk: reg.jwk, alg: reg.alg, signCount: reg.signCount };
    const good = a.get({ challenge: 'c2Vjb25k' });
    const v = verifyAssertion(good, 'c2Vjb25k', RP, cred);
    assert.ok(v.ok, !v.ok ? v.reason : '');
    const sig = Buffer.from(good.response.signature, 'base64url');
    sig[sig.length - 1]! ^= 0x01;
    const forged = { ...good, response: { ...good.response, signature: sig.toString('base64url') } };
    assert.ok(!verifyAssertion(forged, 'c2Vjb25k', RP, { ...cred, signCount: 0 }).ok);
    const other = new SoftAuthenticator(alg, RP.origin, RP.rpId);
    assert.ok(!verifyAssertion(other.get({ challenge: CH }), CH, RP, { ...cred, signCount: 0 }).ok);
  });
}

test('registration refuses wrong challenge / origin / rpId / missing UV', () => {
  const a = new SoftAuthenticator(-7, RP.origin, RP.rpId);
  const opts = { challenge: CH, user: { id: 'dXNlcg' } };
  const r1 = verifyRegistration(a.create(opts), 'b3RoZXI', RP);
  assert.ok(!r1.ok && /challenge/.test(r1.reason));
  const r2 = verifyRegistration(a.create(opts, { origin: 'https://evil.test' }), CH, RP);
  assert.ok(!r2.ok && /origin/.test(r2.reason));
  const r3 = verifyRegistration(a.create(opts, { rpId: 'evil.test' }), CH, RP);
  assert.ok(!r3.ok && /rpId/.test(r3.reason));
  a.flags = 0x01; // present but not verified
  const r4 = verifyRegistration(a.create(opts), CH, RP);
  assert.ok(!r4.ok && /verified/.test(r4.reason));
});

test('assertion refuses a forged signature, a foreign key, and a counter going backwards', () => {
  const a = new SoftAuthenticator(-7, RP.origin, RP.rpId, { counting: true });
  const reg = verifyRegistration(a.create({ challenge: CH, user: { id: 'dXNlcg' } }), CH, RP);
  assert.ok(reg.ok);
  const cred = { jwk: reg.jwk, alg: reg.alg, signCount: reg.signCount };

  const good = a.get({ challenge: CH });
  const tampered = { ...good, response: { ...good.response, signature: good.response.signature.slice(0, -4) + 'AAAA' } };
  assert.ok(!verifyAssertion(tampered, CH, RP, cred).ok);

  const other = new SoftAuthenticator(-7, RP.origin, RP.rpId);
  assert.ok(!verifyAssertion(other.get({ challenge: CH }), CH, RP, cred).ok);

  const v = verifyAssertion(a.get({ challenge: CH }), CH, RP, cred);
  assert.ok(v.ok);
  const replayed = verifyAssertion(a.get({ challenge: CH }), CH, RP, { ...cred, signCount: v.signCount + 5 });
  assert.ok(!replayed.ok && /counter/.test(replayed.reason));
});

test('synced passkeys (counter always 0) are fine', () => {
  const a = new SoftAuthenticator(-8, RP.origin, RP.rpId); // never counts
  const reg = verifyRegistration(a.create({ challenge: CH, user: { id: 'dXNlcg' } }), CH, RP);
  assert.ok(reg.ok);
  for (let i = 0; i < 3; i++) assert.ok(verifyAssertion(a.get({ challenge: CH }), CH, RP, { jwk: reg.jwk, alg: reg.alg, signCount: 0 }).ok);
});

test('CBOR reader: round-trips, refuses truncation and runaway nesting', () => {
  const m = new Map<unknown, unknown>([[1, 2], [-1, Buffer.from([1, 2, 3])], ['fmt', 'none']]);
  const out = cborDecode(cbor(m)).value as Map<unknown, unknown>;
  assert.equal(out.get(1), 2);
  assert.deepEqual(out.get(-1), Buffer.from([1, 2, 3]));
  assert.equal(out.get('fmt'), 'none');
  assert.throws(() => cborDecode(cbor(m).subarray(0, 5)), /truncated/);
  assert.throws(() => cborDecode(Buffer.alloc(40, 0x81)), /too deep/); // [[[[…
  assert.throws(() => cborDecode(Buffer.from([0x5a, 0xff, 0xff, 0xff, 0xff])), /truncated/);
});
