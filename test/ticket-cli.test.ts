// `hn ticket add | ls | rm`: the real CLI, spawned against a scratch data dir.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TicketStore } from '../src/tickets.js';
import { AccountStore } from '../src/accounts.js';

const ROOT = join(import.meta.dirname, '..');

function scratch(opts: { defaults?: boolean } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'hn-ticket-cli-'));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({ principals: [] }));
  writeFileSync(join(dir, 'audiences.json'), JSON.stringify({
    members: { redirect: 'https://members.test/auth', requiredScopes: ['members:member'] },
    extra: { redirect: 'https://extra.test/auth' },
  }));
  if (opts.defaults !== false) {
    writeFileSync(join(dir, 'ticket-defaults.json'), JSON.stringify({
      audiences: ['members'], scopes: ['members:member'], allowed: { audiences: ['members', 'extra'], scopes: ['members:member', 'extra:use'] },
    }));
  }
  const hn = (...args: string[]) => {
    const r = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', 'ticket', ...args], {
      cwd: ROOT, encoding: 'utf8', env: { ...process.env, HN_DATA_DIR: dir, HN_CONFIG_DIR: dir, HN_PUBLIC_URL: 'https://id.test' },
    });
    return { status: r.status, out: `${r.stdout}${r.stderr}` };
  };
  return { dir, hn, store: () => new TicketStore(join(dir, 'tickets.json')), accounts: () => new AccountStore(join(dir, 'accounts.json')) };
}

test('cli: ticket add takes the configured defaults, or its own flags within the allowlist; refuses a bad address, an unknown audience, a repeat', () => {
  const { dir, hn, store } = scratch();
  const r = hn('add', 'Pat.Buyer@gmail.com', '--note', 'front row', '--name', 'Pat');
  assert.equal(r.status, 0, r.out);
  assert.match(r.out, /ticket for Pat\.Buyer@gmail\.com → members \[members:member\]/);
  assert.match(r.out, /\/login\?audience=members&email=Pat\.Buyer%40gmail\.com/);
  const t = store().byEmail('patbuyer@gmail.com')!;
  assert.equal(t.email, 'Pat.Buyer@gmail.com');
  assert.match(t.source, /^admin:/);
  assert.equal(t.note, 'front row');
  assert.equal(t.name, 'Pat');
  assert.deepEqual([t.audiences, t.scopes], [['members'], ['members:member']]);
  assert.equal(statSync(join(dir, 'tickets.json')).mode & 0o777, 0o600);
  const own = hn('add', 'vip@example.org', '--audiences', 'members,extra', '--scopes', 'members:member,extra:use');
  assert.equal(own.status, 0, own.out);
  assert.deepEqual(store().byEmail('vip@example.org')!.audiences, ['members', 'extra']);
  assert.deepEqual(store().byEmail('vip@example.org')!.scopes, ['members:member', 'extra:use']);
  const dup = hn('add', 'patbuyer+again@gmail.com');
  assert.notEqual(dup.status, 0);
  assert.match(dup.out, /already holds a ticket/);
  assert.notEqual(hn('add', 'nope').status, 0);
  assert.match(hn('add', 'x@y.co', '--audiences', 'nowhere').out, /not one a ticket may carry/);
  assert.match(hn('add', 'x@y.co', '--audiences', 'console').out, /this node’s own/);
  assert.match(hn('add', 'x@y.co', '--scopes', 'worlds:join').out, /scope "worlds:join"/);
  assert.equal(store().all().length, 2);
});

test('cli: ticket ls shows holders and who took a ticket up; rm stops sign-ups and says the account stays', () => {
  const { hn, store } = scratch();
  hn('add', 'a@example.org');
  hn('add', 'b@example.org');
  store().claim('b@example.org', 'human:email:abc');
  const ls = hn('ls');
  assert.equal(ls.status, 0);
  assert.match(ls.out, /tickets \(2\):/);
  assert.match(ls.out, /a@example\.org .* unused/);
  assert.match(ls.out, /b@example\.org .* taken up by human:email:abc/);
  assert.equal(JSON.parse(hn('ls', '--json').out).length, 2);
  const rmUnused = hn('rm', 'A@example.org');
  assert.equal(rmUnused.status, 0, rmUnused.out);
  assert.match(rmUnused.out, /had not been taken up/);
  const rmUsed = hn('rm', 'b@example.org');
  assert.match(rmUsed.out, /Its account \(human:email:abc\) stays/);
  assert.equal(store().all().length, 0);
  assert.notEqual(hn('rm', 'b@example.org').status, 0);
});

test('cli: ticket rm takes back what the ticket gave its account (the account stays)', () => {
  const { hn, store, accounts } = scratch();
  hn('add', 'c@example.org');
  accounts().add({
    sub: 'human:email:c1', email: { address: 'c@example.org', verifiedAt: '' }, createdAt: '',
    ticket: { email: 'c@example.org', source: 'admin:x', claimedAt: '', audiences: ['members'], scopes: ['members:member'] },
  });
  store().claim('c@example.org', 'human:email:c1');
  const r = hn('rm', 'c@example.org');
  assert.equal(r.status, 0, r.out);
  assert.match(r.out, /loses what the ticket gave and stays/);
  const a = accounts().bySub('human:email:c1')!;
  assert.equal(a.ticket, undefined);
  assert.equal(a.email!.address, 'c@example.org');
});

test('cli: without config/ticket-defaults.json no ticket can be made, flags or not', () => {
  const { hn, store } = scratch({ defaults: false });
  for (const args of [['add', 'a@example.org'], ['add', 'a@example.org', '--audiences', 'members']]) {
    const r = hn(...args);
    assert.notEqual(r.status, 0);
    assert.match(r.out, /no config\/ticket-defaults\.json/);
  }
  assert.equal(store().all().length, 0);
});
