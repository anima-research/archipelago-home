import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { InviteStore } from '../src/stores.js';
import { delegableScopes, mintSponsoredInvite } from '../src/console.js';
import { audiencesFor, consoleRequiredScopes, invitePolicyProblem, invitePolicyStore, NO_POLICY } from '../src/policy.js';
import { HomeNode } from '../src/server.js';

const fresh = () => mkdtempSync(join(tmpdir(), 'hn-policy-'));

// A different home altogether: none of Anima's services.
const GARDEN = {
  console: { requiredScopes: ['garden:tend'] },
  primaryAudience: 'garden',
  scopes: {
    'garden:tend': ['delegable', 'resident'],
    'garden:prune': ['anchorGrantable', 'resident'],
    'library:read': ['delegable', 'baseline'],
    'vault:open': ['resident'],
  },
  audiences: [
    { audience: 'library', always: true },
    { audience: 'garden', when: ['garden:*'] },
    { audience: 'vault', anchored: true },
    { audience: 'plot-*', when: ['garden:tend'] },
  ],
};

test('another home brings its own policy: scopes, baseline, anchoring and audiences all come from it', () => {
  const dir = fresh();
  writeFileSync(join(dir, 'invites.json'), JSON.stringify(GARDEN));
  const policy = invitePolicyStore(join(dir, 'invites.json')).get();
  assert.equal(policy.configured, true);
  const invites = new InviteStore(join(dir, 'store.json'));
  const gardener = { sub: 'human:local:ann', name: 'ann', scopes: ['garden:tend', 'library:read', 'worlds:join'] };

  const r = mintSponsoredInvite(invites, policy, gardener, 'helper', { knownAudiences: ['plot-b', 'garden', 'plot-a', 'library'] });
  assert.ok(r.ok);
  assert.deepEqual(r.invite.scopes, ['garden:tend', 'library:read']); // worlds:join means nothing here
  assert.deepEqual(r.invite.audiences, ['garden', 'library', 'plot-a', 'plot-b']); // primary first, globs per registered world

  // anchoring: the resident grant, anchor-grantable only for id:anchor holders
  const keeper = { ...gardener, sub: 'human:local:kay', scopes: ['garden:tend', 'id:anchor'] };
  assert.deepEqual(delegableScopes(policy, keeper.scopes), ['garden:tend', 'garden:prune']);
  const a = mintSponsoredInvite(invites, policy, keeper, 'resident', { anchorDomain: 'id.garden' });
  assert.ok(a.ok);
  assert.deepEqual([...a.invite.scopes].sort(), ['garden:prune', 'garden:tend', 'library:read', 'vault:open']);
  assert.ok(a.invite.audiences!.includes('vault'));

  // the console gate is the policy's too
  const outsider = mintSponsoredInvite(invites, policy, { ...gardener, sub: 'human:local:zed', scopes: ['worlds:join'] }, undefined);
  assert.ok(!outsider.ok && /garden:tend/.test(outsider.error));
});

test('no policy: the console mints nothing and says why', () => {
  assert.equal(consoleRequiredScopes(NO_POLICY), null);
  const dir = fresh();
  const missing = invitePolicyStore(join(dir, 'nope.json')).get();
  assert.equal(missing.configured, false);
  const r = mintSponsoredInvite(new InviteStore(join(dir, 'store.json')), missing, { sub: 'human:local:a', name: 'a', scopes: ['worlds:join'] }, undefined);
  assert.ok(!r.ok && r.status === 403 && /no invite policy/.test(r.error));
});

test('a typo refuses the whole file; a hot reload keeps the last good policy', async () => {
  assert.match(invitePolicyProblem({ scopes: { 'a:b': ['delegible'] }, audiences: [] })!, /unknown role "delegible"/);
  assert.match(invitePolicyProblem({ scopes: {}, audiences: [{ audience: 'x', whne: ['a:b'] }] })!, /unknown key "whne"/);
  assert.match(invitePolicyProblem({ scopes: {}, audiences: [{ audience: 'x' }] })!, /never applies/);
  assert.match(invitePolicyProblem({ scopes: {}, audiences: [], consoel: {} })!, /unknown key "consoel"/);
  assert.equal(invitePolicyProblem({ _: 'comment', scopes: { _note: 'x' }, audiences: [] }), null);

  const dir = fresh();
  const path = join(dir, 'invites.json');
  writeFileSync(path, JSON.stringify(GARDEN));
  const store = invitePolicyStore(path);
  store.startWatching(20);
  try {
    writeFileSync(path, JSON.stringify({ ...GARDEN, scopes: { 'garden:tend': ['delegible'] } }));
    await new Promise((r) => setTimeout(r, 120));
    assert.deepEqual(store.get().scopes, GARDEN.scopes); // the broken file was refused
    writeFileSync(path, JSON.stringify({ ...GARDEN, console: { requiredScopes: ['library:read'] } }));
    await new Promise((r) => setTimeout(r, 120));
    assert.deepEqual(consoleRequiredScopes(store.get()), ['library:read']); // a good edit lands without a restart
  } finally {
    store.stopWatching();
  }
});

test('audience rules: always, anchored, when (exact and prefix), primary first, globs over registered audiences', () => {
  const p = { configured: true, primaryAudience: 'b', scopes: {}, audiences: [
    { audience: 'a', always: true }, { audience: 'b', when: ['x:*'] }, { audience: 'c', anchored: true },
    { audience: 'w-*', when: ['y:go'] }, { audience: 'a', when: ['x:*'] },
  ] };
  assert.deepEqual(audiencesFor(p, ['x:one'], false), ['b', 'a']);
  assert.deepEqual(audiencesFor(p, ['z:one'], false), ['a']);
  assert.deepEqual(audiencesFor(p, [], true), ['a', 'c']);
  assert.deepEqual(audiencesFor(p, ['y:go'], false, ['w-2', 'v-1', 'w-1']), ['a', 'w-1', 'w-2']);
  assert.deepEqual(audiencesFor(p, ['y:gone'], false, ['w-1']), ['a']); // exact match only without :*
});

test('end to end: a node without invites.json has no console; adding the file turns it on, no restart', async () => {
  const dir = fresh();
  writeFileSync(join(dir, 'audiences.json'), '{}');
  const node = new HomeNode({ iss: 'id.test', publicUrl: 'https://id.test', bind: '127.0.0.1', port: 0, dataDir: dir, configDir: dir });
  const base = `http://127.0.0.1:${await node.start()}`;
  try {
    const me = await fetch(`${base}/console/me`, { headers: { authorization: 'Bearer x' } });
    assert.equal(me.status, 503);
    assert.match((await me.json()).error, /no invite policy/);
    writeFileSync(join(dir, 'invites.json'), JSON.stringify(GARDEN));
    node.invitePolicy.refresh();
    assert.equal(node.invitePolicy.get().configured, true);
    const me2 = await fetch(`${base}/console/me`, { headers: { authorization: 'Bearer x' } });
    assert.equal(me2.status, 401); // the console is on now: it's the token that's wrong
  } finally {
    node.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});
