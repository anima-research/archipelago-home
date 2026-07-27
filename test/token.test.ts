import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey } from '../src/keys.js';
import { JtiCache, mintToken, parseTtl, verifyToken, type Aid1Payload } from '../src/token.js';

const issuer = generateKey();
const other = generateKey();

function payload(over: Partial<Aid1Payload> = {}): Aid1Payload {
  const now = Math.floor(Date.now() / 1000);
  return {
    v: 1,
    iss: 'id.test',
    sub: 'agent:fable@animalabs.ai',
    kind: 'agent',
    name: 'Fable',
    aud: 'eidoverse',
    scopes: ['worlds:join'],
    iat: now,
    exp: now + 3600,
    ...over,
  };
}

const OPTS = { issuerId: issuer.id, iss: 'id.test', aud: 'eidoverse' };

test('mint → verify round-trip', () => {
  const tok = mintToken(issuer.privateKey, payload());
  const v = verifyToken(tok, OPTS);
  assert.ok(v.ok);
  assert.equal(v.payload.sub, 'agent:fable@animalabs.ai');
  assert.deepEqual(v.payload.scopes, ['worlds:join']);
});

test('tampered payload fails signature', () => {
  const tok = mintToken(issuer.privateKey, payload());
  const [p, seg, sig] = tok.split('.') as [string, string, string];
  const evil = JSON.parse(Buffer.from(seg, 'base64url').toString());
  evil.scopes = ['worlds:join', 'admin'];
  const tampered = `${p}.${Buffer.from(JSON.stringify(evil)).toString('base64url')}.${sig}`;
  const v = verifyToken(tampered, OPTS);
  assert.ok(!v.ok && v.reason === 'signature verify failed');
});

test('wrong issuer key fails', () => {
  const tok = mintToken(other.privateKey, payload());
  const v = verifyToken(tok, OPTS);
  assert.ok(!v.ok && v.reason === 'signature verify failed');
});

test('audience and issuer mismatches fail', () => {
  const tok = mintToken(issuer.privateKey, payload());
  assert.ok(!verifyToken(tok, { ...OPTS, aud: 'orrery' }).ok);
  assert.ok(!verifyToken(tok, { ...OPTS, iss: 'id.evil' }).ok);
});

test('expiry enforced', () => {
  const now = Math.floor(Date.now() / 1000);
  const tok = mintToken(issuer.privateKey, payload({ exp: now - 10 }));
  const v = verifyToken(tok, OPTS);
  assert.ok(!v.ok && v.reason === 'expired');
});

test('requireScopes enforced', () => {
  const tok = mintToken(issuer.privateKey, payload());
  assert.ok(verifyToken(tok, { ...OPTS, requireScopes: ['worlds:join'] }).ok);
  const v = verifyToken(tok, { ...OPTS, requireScopes: ['worlds:build'] });
  assert.ok(!v.ok && v.reason === 'missing scope worlds:build');
});

test('garbage inputs fail cleanly', () => {
  for (const bad of ['', 'aid1', 'aid1.x', 'aid1.x.y.z', 'jwt.ey.sig', 'aid1.!!!.???']) {
    assert.ok(!verifyToken(bad, OPTS).ok, bad);
  }
});

test('JtiCache single-use', () => {
  const c = new JtiCache();
  const exp = Math.floor(Date.now() / 1000) + 600;
  assert.ok(c.claim('a', exp));
  assert.ok(!c.claim('a', exp));
  assert.ok(c.claim('b', exp));
});

test('parseTtl', () => {
  assert.equal(parseTtl('10m'), 600_000);
  assert.equal(parseTtl('72h'), 72 * 3_600_000);
  assert.equal(parseTtl('14d'), 14 * 86_400_000);
  assert.throws(() => parseTtl('1w'));
});
