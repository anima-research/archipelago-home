import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { audiencesStore, anyOpen, grantForRoles, signupGrant, InviteStore, mcplDirectory, openSites, PrincipalStore, serviceDirectory, type RolesConfig } from '../src/stores.js';

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

test('service directory publishes only audiences with a usable https api base', () => {
  const dir = serviceDirectory({
    eidoverse: { redirect: 'https://eidoverse.animalabs.ai/auth' }, // MCPL-only: no api
    music: { redirect: 'https://music.animalabs.ai/auth', api: 'https://music.animalabs.ai' },
    orrery: { redirect: 'https://orrery.animalabs.ai/auth', api: 'https://orrery.animalabs.ai/' },
  });
  // present only when an api base is declared; trailing slash normalised
  assert.deepEqual(dir, {
    music: 'https://music.animalabs.ai',
    orrery: 'https://orrery.animalabs.ai',
  });
});

test('mcpl directory publishes only audiences with a wss endpoint, and the endpoint as given', () => {
  const dir = mcplDirectory({
    body: { redirect: 'https://body.example/health', mcpl: 'wss://body.example:8865/' },
    docs: { redirect: 'https://docs.example/auth', api: 'https://docs.example' }, // HTTP seam only
    plaintext: { redirect: 'https://a/auth', mcpl: 'ws://10.0.0.7:8765/' }, // a host must not send a credential there
    https: { redirect: 'https://b/auth', mcpl: 'https://b.example/mcpl' }, // not an MCPL scheme
    empty: { redirect: 'https://c/auth', mcpl: '' },
    spaced: { redirect: 'https://d/auth', mcpl: 'wss://evil .example' },
    notAString: { redirect: 'https://e/auth', mcpl: 42 as unknown as string },
  });
  assert.deepEqual(dir, { body: 'wss://body.example:8865/' });
  // an api base says nothing about an MCPL door, and the reverse
  assert.deepEqual(serviceDirectory({ body: { redirect: 'https://body.example/health', mcpl: 'wss://body.example:8865/' } }), {});
});

test('service directory refuses bases a bearer credential must not be attached to', () => {
  const dir = serviceDirectory({
    plaintext: { redirect: 'https://a/auth', api: 'http://music.animalabs.ai' },
    empty: { redirect: 'https://b/auth', api: '' },
    spaced: { redirect: 'https://c/auth', api: 'https://evil .example' },
    notAString: { redirect: 'https://d/auth', api: 42 as unknown as string },
  });
  assert.deepEqual(dir, {});
});

test('audiences: a malformed signup is refused (the last good file stays); openSites falls back to the redirect', () => {
  const dir = mkdtempSync(join(tmpdir(), 'aud-'));
  const path = join(dir, 'audiences.json');
  const good = { notes: { redirect: 'https://notes.test/auth', api: '', requiredScopes: ['notes:use'], signup: {} } };
  writeFileSync(path, JSON.stringify(good));
  const store = audiencesStore(path);
  assert.deepEqual(store.get(), good);
  assert.deepEqual(openSites(store.get()), [{ audience: 'notes', url: 'https://notes.test', host: 'notes.test' }]);
  const bad: Array<Record<string, unknown>> = [
    { signup: [] }, { signup: { scopes: ['notes:use', 7] } }, { signup: { scopes: 'notes:use' } }, { signup: { scopes: [''] } }, { signup: null },
    { signup: { scopes: [] } }, // doesn't cover requiredScopes: every newcomer would be refused
    { requiredScopes: [42] }, { requiredScopes: 'notes:use' },
  ];
  let tick = 1;
  for (const change of bad) {
    writeFileSync(path, JSON.stringify({ notes: { ...good.notes, ...change } }));
    utimesSync(path, new Date(), new Date(Date.now() + 1000 * tick++)); // its own mtime, so refresh really reads it
    assert.deepEqual(audiencesStore(path).get(), {}, JSON.stringify(change)); // refused at load: the fallback, not an open audience
    // a running store keeps its last good file through the same bad edit
    store.refresh();
    assert.deepEqual(store.get(), good, JSON.stringify(change));
  }
  // …and does read the next good one (refresh isn't just keeping what it had)
  const good2 = { notes: { ...good.notes, requiredScopes: null, signup: {} }, other: { redirect: 'https://other.test/auth' } };
  writeFileSync(path, JSON.stringify(good2));
  utimesSync(path, new Date(), new Date(Date.now() + 1000 * tick++));
  store.refresh();
  assert.deepEqual(store.get(), good2); // requiredScopes: null still reads as none
});

test('JsonStore: a broken file is retried until it reads — even a repair that keeps the mtime', () => {
  const dir = mkdtempSync(join(tmpdir(), 'aud-'));
  const path = join(dir, 'audiences.json');
  writeFileSync(path, '{ broken');
  const when = new Date(Date.now() - 60_000);
  utimesSync(path, when, when);
  const store = audiencesStore(path);
  writeFileSync(path, JSON.stringify({ a: { redirect: 'https://a.test/auth' } }));
  utimesSync(path, when, when); // same mtime as the broken file
  store.refresh();
  assert.deepEqual(Object.keys(store.get()), ['a']);
});

test('openSites: points newcomers at the service (its redirect origin), not its API host; skips what isn’t a site', () => {
  const all = {
    app: { redirect: 'https://app.example/auth', api: 'https://api.example/v1', signup: {} },
    shut: { redirect: 'https://shut.example/auth' },
    badredir: { redirect: 'not a url', api: 'https://api.bad.example', signup: {} },
    mail: { redirect: 'mailto:someone@example.com', signup: {} },
  };
  assert.deepEqual(openSites(all), [
    { audience: 'app', url: 'https://app.example', host: 'app.example' },
    { audience: 'badredir', url: 'https://api.bad.example', host: 'api.bad.example' },
  ]);
});

test('signupGrant: account and console never take one, whatever audiences.json says', () => {
  const all = {
    console: { redirect: 'https://x.test/auth', signup: { scopes: ['worlds:join'] } },
    account: { redirect: 'https://x.test/auth', signup: {} },
    docs: { redirect: 'https://docs.test/auth', requiredScopes: ['docs:use'], signup: {} },
  };
  assert.equal(signupGrant(all, 'console'), null);
  assert.equal(signupGrant(all, 'account'), null);
  assert.deepEqual(signupGrant(all, 'docs'), { scopes: ['docs:use'] });
  assert.equal(anyOpen({ console: all.console, account: all.account }), false);
});
