// `hn user add --google` against a row a sign-in already made: the real CLI,
// spawned against a scratch data dir, so the promises hold end to end.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AccountStore, type HumanAccount } from '../src/accounts.js';

const ROOT = join(import.meta.dirname, '..');

function scratch(rows: HumanAccount[]) {
  const dir = mkdtempSync(join(tmpdir(), 'hn-cli-'));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({ principals: [] }));
  const file = join(dir, 'accounts.json');
  const seed = new AccountStore(file);
  for (const r of rows) seed.add(r);
  const hn = (...args: string[]) => {
    const r = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', 'user', ...args], {
      cwd: ROOT, encoding: 'utf8', env: { ...process.env, HN_DATA_DIR: dir, HN_CONFIG_DIR: dir },
    });
    return { status: r.status, out: `${r.stdout}${r.stderr}` };
  };
  return { hn, rows: () => new AccountStore(file).all() };
}

const at = '2026-10-30T00:00:00Z';
/** What a Google sign-in at an open audience leaves behind. */
const signedUp = (gsub: string, email: string, extra: Partial<HumanAccount> = {}): HumanAccount => ({
  sub: `human:google:${gsub}`, createdAt: at, notes: 'signed up at docs',
  google: { sub: gsub, email, verified: true, name: 'Someone', linkedAt: at }, ...extra,
});

test('cli: user add --google adopts a verified sign-up row — same sub, links and codes kept', () => {
  const { hn, rows } = scratch([signedUp('g1', 'jo.anne@gmail.com', { codes: [{ id: 'code_1', at }] })]);
  const r = hn('add', 'joanne', '--google', 'JoAnne@gmail.com', '--scopes', 'docs:use,worlds:join', '--name', 'Jo Anne', '--tier', 'x');
  assert.equal(r.status, 0, r.out);
  assert.match(r.out, /already has an account \(human:google:g1/);
  const all = rows();
  assert.equal(all.length, 1); // no second account
  const a = all[0]!;
  assert.equal(a.sub, 'human:google:g1');
  assert.equal(a.username, 'joanne');
  assert.equal(a.name, 'Jo Anne');
  assert.deepEqual(a.scopes, ['docs:use', 'worlds:join']);
  assert.deepEqual(a.claims, { tier: 'x' });
  assert.equal(a.google?.sub, 'g1');
  assert.deepEqual(a.codes, [{ id: 'code_1', at }]);
  assert.match(a.notes!, /^signed up at docs; hn user add /);
});

test('cli: its own display name does not block the username', () => {
  const { hn, rows } = scratch([signedUp('g2', 'al@gmail.com', { name: 'alice' })]);
  const r = hn('add', 'alice', '--google', 'al@gmail.com');
  assert.equal(r.status, 0, r.out);
  assert.equal(rows()[0]!.username, 'alice');
});

test('cli: never adopted — unverified address, operator grants, a username, disabled', () => {
  const cases: Array<[string, HumanAccount, RegExp]> = [
    ['unverified', signedUp('g3', 'u@gmail.com', { google: { sub: 'g3', email: 'u@gmail.com', linkedAt: at } }), /hasn't vouched/],
    ['granted', signedUp('g4', 'v@gmail.com', { scopes: ['x:y'] }), /already on human:google:g4 \(linked\)$/m],
    ['named', signedUp('g5', 'w@gmail.com', { username: 'wendy' }), /already on human:google:g5 \(linked\)$/m],
    ['disabled', signedUp('g6', 'x@gmail.com', { disabled: true }), /already on human:google:g6/],
  ];
  for (const [label, row, msg] of cases) {
    const { hn, rows } = scratch([row]);
    const before = JSON.stringify(rows());
    const r = hn('add', `new-${label}`, '--google', row.google!.email, '--scopes', 'docs:use');
    assert.notEqual(r.status, 0, `${label}: ${r.out}`);
    assert.match(r.out, msg, label);
    assert.equal(JSON.stringify(rows()), before, `${label}: nothing written`);
  }
});

test('cli: user set --google onto a sign-up row’s address refuses and names the command to run', () => {
  const { hn } = scratch([signedUp('g7', 'p@gmail.com'), { sub: 'human:local:pat', username: 'pat', createdAt: at }]);
  const r = hn('set', 'pat', '--google', 'p@gmail.com');
  assert.notEqual(r.status, 0);
  assert.match(r.out, /hn user set human:google:g7 --scopes/);
});

test('cli: a fresh address is still an invite on a new local account', () => {
  const { hn, rows } = scratch([signedUp('g8', 'q@gmail.com')]);
  const r = hn('add', 'fresh', '--google', 'fresh@gmail.com', '--scopes', 'docs:use');
  assert.equal(r.status, 0, r.out);
  const f = rows().find((a) => a.sub === 'human:local:fresh')!;
  assert.deepEqual(f.google, { email: 'fresh@gmail.com' });
  assert.deepEqual(f.scopes, ['docs:use']);
});
