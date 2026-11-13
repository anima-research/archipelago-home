import { test } from 'node:test';
import assert from 'node:assert/strict';
import { emailKey, identityFromIdToken } from '../src/google.js';

const b64j = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (c: Record<string, unknown>) => `${b64j({ alg: 'RS256' })}.${b64j(c)}.sig`;
const NOW = 1_800_000_000;
const good = { iss: 'https://accounts.google.com', aud: 'cid', exp: NOW + 300, sub: '123', email: 'a@b.co', email_verified: true, name: 'A' };

test('id_token: iss, aud, exp and sub are checked', () => {
  assert.deepEqual(identityFromIdToken(jwt(good), 'cid', NOW), { sub: '123', email: 'a@b.co', emailVerified: true, name: 'A' });
  assert.equal(identityFromIdToken(jwt({ ...good, iss: 'accounts.google.com' }), 'cid', NOW).sub, '123');
  assert.throws(() => identityFromIdToken(jwt({ ...good, iss: 'https://evil.example' }), 'cid', NOW), /issuer/);
  assert.throws(() => identityFromIdToken(jwt({ ...good, aud: 'other' }), 'cid', NOW), /client/);
  assert.throws(() => identityFromIdToken(jwt({ ...good, exp: NOW - 3600 }), 'cid', NOW), /expired/);
  assert.throws(() => identityFromIdToken(jwt({ ...good, sub: '' }), 'cid', NOW), /sub/);
  assert.throws(() => identityFromIdToken('garbage', 'cid', NOW), /unreadable/);
  assert.equal(identityFromIdToken(jwt({ ...good, email_verified: false }), 'cid', NOW).emailVerified, false);
});

test('emailKey: case-insensitive; Gmail ignores dots and +suffix; other domains keep them', () => {
  assert.equal(emailKey(' Grace.Hopper+hn@GMail.com '), 'gracehopper@gmail.com');
  assert.equal(emailKey('grace.hopper@googlemail.com'), 'gracehopper@gmail.com');
  assert.equal(emailKey('Grace.Hopper+x@navy.example'), 'grace.hopper+x@navy.example');
});
