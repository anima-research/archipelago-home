import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  AccountStore, hashPassword, looksLikeRecoveryCode, mergeGrants, newRecoveryCodes, normalizeRecovery, passwordProblem,
  sha256hex, usernameProblem, verifyPassword,
} from '../src/accounts.js';

const fresh = () => {
  const dir = mkdtempSync(join(tmpdir(), 'hn-acct-'));
  return { dir, path: join(dir, 'accounts.json'), store: new AccountStore(join(dir, 'accounts.json')) };
};

test('passwords: scrypt round trip, wrong password and absent hash refused', async () => {
  const h = await hashPassword('correct horse battery');
  assert.match(h, /^scrypt\$15\$8\$1\$/);
  assert.equal(await verifyPassword('correct horse battery', h), true);
  assert.equal(await verifyPassword('correct horse batterz', h), false);
  assert.equal(await verifyPassword('anything', undefined), false);
  assert.equal(passwordProblem('short'), 'passwords need at least 10 characters');
  assert.match(passwordProblem('alice-is-great', 'alice') ?? '', /besides your username/);
  assert.equal(passwordProblem('dee password 1', 'dee'), null);
  assert.equal(passwordProblem('a perfectly fine one'), null);
});

test('usernames: shape, reserved, taken (accounts and principal names)', () => {
  const { store } = fresh();
  store.add({ sub: 'human:local:taken', username: 'taken', createdAt: '' });
  const agentNames = (n: string) => n === 'fable';
  assert.equal(usernameProblem('ok-name', store, agentNames), null);
  assert.equal(usernameProblem('OK-Name ', store, agentNames), null); // normalized
  assert.match(usernameProblem('ab', store, agentNames)!, /3–32/);
  assert.match(usernameProblem('-edge', store, agentNames)!, /3–32/);
  assert.match(usernameProblem('admin', store, agentNames)!, /reserved/);
  assert.match(usernameProblem('Taken', store, agentNames)!, /taken/);
  assert.match(usernameProblem('fable', store, agentNames)!, /taken/);
});

test('recovery codes: ten, distinct, hashed, recognisable', () => {
  const { codes, hashes } = newRecoveryCodes();
  assert.equal(new Set(codes).size, 10);
  for (const [i, c] of codes.entries()) {
    assert.match(c, /^[a-z2-9]{5}-[a-z2-9]{5}$/);
    assert.ok(looksLikeRecoveryCode(c.toUpperCase()));
    assert.equal(hashes[i], sha256hex(normalizeRecovery(` ${c.toUpperCase()} `)));
  }
  assert.ok(!looksLikeRecoveryCode('123456'));
});

test('store: 0600 file, lookups, uniqueness, and a CLI edit is seen before the next write', () => {
  const { path, store } = fresh();
  store.add({ sub: 'human:discord:1', discord: { id: '1' }, createdAt: '' });
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.throws(() => store.add({ sub: 'human:local:x', discord: { id: '1' }, createdAt: '' }), /linked elsewhere/);
  assert.equal(store.byDiscord('1')?.sub, 'human:discord:1');

  // another process (hn user add) writes the file directly…
  const other = new AccountStore(path);
  other.add({ sub: 'human:local:bob', username: 'bob', createdAt: '' });
  // …and this store's next update doesn't clobber it
  store.update('human:discord:1', (a) => ({ ...a, username: 'one' }));
  const final = new AccountStore(path).all().map((a) => a.sub).sort();
  assert.deepEqual(final, ['human:discord:1', 'human:local:bob']);
});

test('store: a hand-edit that breaks the file keeps the previous good state', () => {
  const { path, store } = fresh();
  store.add({ sub: 'human:local:a', username: 'a1a', createdAt: '' });
  writeFileSync(path, '{ not json');
  assert.equal(store.all().length, 1);
});

test('grant merge: union of scopes, later claims win, all-null → null', () => {
  assert.equal(mergeGrants(null, undefined), null);
  assert.deepEqual(mergeGrants({ scopes: ['a', 'b'], claims: { tier: 'x' } }, { scopes: ['b', 'c'], claims: { tier: 'y' } }), {
    scopes: ['a', 'b', 'c'], claims: { tier: 'y' },
  });
  assert.deepEqual(mergeGrants(null, { scopes: [] }), { scopes: [] });
});
