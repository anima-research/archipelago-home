import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { grantForRoles, InviteStore, PrincipalStore, type RolesConfig } from '../src/stores.js';

function tmp(): string {
  return mkdtempSync(join(tmpdir(), 'hn-stores-'));
}

test('principal add/revoke persists atomically', () => {
  const dir = tmp();
  const path = join(dir, 'principals.json');
  const store = new PrincipalStore(path);
  store.add({ sub: 'agent:a@guest', name: 'A', kind: 'agent', key: null, scopes: ['x'] });
  assert.throws(() => store.add({ sub: 'agent:a@guest', name: 'B', kind: 'agent', key: null, scopes: [] }));
  assert.throws(() => store.add({ sub: 'agent:b@guest', name: 'a', kind: 'agent', key: null, scopes: [] })); // name, case-insensitive
  assert.ok(store.revoke('agent:a@guest'));
  const onDisk = JSON.parse(readFileSync(path, 'utf8'));
  assert.ok(onDisk.principals[0].expires);
  assert.ok(!store.isLive(onDisk.principals[0]));
});

test('malformed principals file → empty, not crash', () => {
  const dir = tmp();
  const path = join(dir, 'principals.json');
  writeFileSync(path, '{ not json');
  const store = new PrincipalStore(path);
  assert.deepEqual(store.all(), []);
});

test('invite lifecycle: check/consume/exhaust/expire', () => {
  const dir = tmp();
  const store = new InviteStore(join(dir, 'invites.json'));
  const inv = store.mint({ scopes: ['worlds:join'], maxUses: 2 });
  assert.ok(inv.code.startsWith('inv_'));
  assert.equal(typeof store.check(inv.code), 'object');
  store.consume(inv.code);
  store.consume(inv.code);
  assert.equal(store.check(inv.code), 'exhausted');
  assert.equal(store.check('nope'), 'unknown');
  const old = store.mint({ scopes: [], expiresAt: new Date(Date.now() - 1000).toISOString() });
  assert.equal(store.check(old.code), 'expired');
});

test('grantForRoles unions scopes, merges claims, null on no match', () => {
  const cfg: RolesConfig = {
    guildId: 'g',
    map: {
      r1: { scopes: ['worlds:join'], claims: { tier: 'event' } },
      r2: { scopes: ['worlds:join', 'worlds:build'], claims: { tier: 'friend' } },
    },
  };
  assert.equal(grantForRoles(['nope'], cfg), null);
  assert.equal(grantForRoles([], cfg), null);
  const g1 = grantForRoles(['r1'], cfg)!;
  assert.deepEqual(g1.scopes, ['worlds:join']);
  assert.deepEqual(g1.claims, { tier: 'event' });
  const g2 = grantForRoles(['r1', 'r2'], cfg)!;
  assert.deepEqual(g2.scopes.sort(), ['worlds:build', 'worlds:join']);
  assert.deepEqual(g2.claims, { tier: 'friend' }); // later role wins ties
});
