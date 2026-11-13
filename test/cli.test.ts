// `hn user add --google` against a row a sign-in already made: the real CLI,
// spawned against a scratch data dir, so the promises hold end to end.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
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
  return { hn, file, rows: () => new AccountStore(file).all() };
}

const at = '2026-10-30T00:00:00Z';
/** What a Google sign-in at an open audience leaves behind. */
const signedUp = (gsub: string, email: string, extra: Partial<HumanAccount> = {}): HumanAccount => ({
  sub: `human:google:${gsub}`, createdAt: at, notes: 'signed up at docs',
  google: { sub: gsub, email, name: 'Someone', linkedAt: at }, ...extra,
});

test('cli: user add --google onto an account a sign-in made is refused — its details and the hn user set to run; nothing written', () => {
  const cases: Array<[HumanAccount, RegExp]> = [
    [signedUp('g1', 'jo.anne@gmail.com', { codes: [{ id: 'code_1', at }] }), /signed up by signing in \("Someone", signed up at docs, Google linked 2026-10-30\)\. To give that account access, check it's them, then: hn user set human:google:g1 --scopes/],
    [signedUp('g2', 'un@gmail.com', { username: 'unny' }), /hn user set unny --scopes/],
    [signedUp('g3', 'off@gmail.com', { disabled: true }), /hn user enable human:google:g3 && hn user set human:google:g3 --scopes/],
    [signedUp('g4', 'v@gmail.com', { scopes: ['x:y'] }), /already on human:google:g4 \(linked\) — they signed up/],
  ];
  for (const [row, msg] of cases) {
    const { hn, rows } = scratch([row]);
    const before = JSON.stringify(rows());
    const r = hn('add', 'someone', '--google', row.google!.email.toUpperCase(), '--scopes', 'docs:use');
    assert.notEqual(r.status, 0, r.out);
    assert.match(r.out, msg);
    assert.equal(JSON.stringify(rows()), before, 'nothing written');
  }
});

test('cli: user set --google can’t change a Google-made account’s link', () => {
  const { hn, rows } = scratch([signedUp('g5', 'mine@gmail.com')]);
  const before = JSON.stringify(rows());
  const r = hn('set', 'human:google:g5', '--google', 'other@gmail.com');
  assert.notEqual(r.status, 0);
  assert.match(r.out, /IS a Google identity/);
  assert.equal(JSON.stringify(rows()), before);
});

test('cli: a store that can’t read its file refuses the write with a one-line error, file untouched', () => {
  const { hn, file } = scratch([]);
  const bad = JSON.stringify({ accounts: [{ sub: 'human:local:keep', createdAt: at }, { sub: 'human:local:bad', withhold: 'x', createdAt: at }] });
  writeFileSync(file, bad);
  const r = hn('add', 'zed', '--google', 'zed@gmail.com');
  assert.notEqual(r.status, 0);
  assert.match(r.out, /^hn: .*accounts\.json can't be read or fails validation — fix it first/m);
  assert.match(hn('ls').out, /can't be read/); // not "accounts (0)"
  assert.doesNotMatch(r.out, /\n\s+at /); // no stack trace
  assert.equal(readFileSync(file, 'utf8'), bad);
});

test('cli: user set --google onto a sign-up row’s address refuses and names the command to run', () => {
  const { hn, rows } = scratch([signedUp('g7', 'p@gmail.com'), { sub: 'human:local:pat', username: 'pat', createdAt: at }]);
  const before = JSON.stringify(rows());
  const r = hn('set', 'pat', '--google', 'p@gmail.com');
  assert.notEqual(r.status, 0);
  assert.match(r.out, /hn user set human:google:g7 --scopes/);
  assert.equal(JSON.stringify(rows()), before);
});

test('cli: restrict with no value, or an empty one, is refused, nothing written', () => {
  const { hn, rows } = scratch([]);
  for (const args of [['--withhold'], ['--withhold', ''], ['--ignore-roles', ','], ['--withhold', ' , ']]) {
    const r = hn('restrict', '139758639064390000', ...args);
    assert.notEqual(r.status, 0, args.join(' '));
    assert.match(r.out, /wants a value/);
    assert.deepEqual(rows(), []);
  }
});

test('cli: a fresh address is still an invite on a new local account', () => {
  const { hn, rows } = scratch([signedUp('g8', 'q@gmail.com')]);
  const r = hn('add', 'fresh', '--google', 'fresh@gmail.com', '--scopes', 'docs:use');
  assert.equal(r.status, 0, r.out);
  const f = rows().find((a) => a.sub === 'human:local:fresh')!;
  assert.deepEqual(f.google, { email: 'fresh@gmail.com' });
  assert.deepEqual(f.scopes, ['docs:use']);
});

test('cli: restrict with a bad flag writes nothing — no stray row for a new Discord id', () => {
  const { hn, rows } = scratch([]);
  const r = hn('restrict', '139758639064390000', '--ignore-roles', 'team');
  assert.notEqual(r.status, 0);
  assert.match(r.out, /role ids/);
  assert.deepEqual(rows(), []);
  const ok = hn('restrict', '139758639064390000', '--ignore-roles', '1391615830604779520');
  assert.equal(ok.status, 0, ok.out);
  assert.deepEqual(rows().map((a) => [a.sub, a.ignoreRoles]), [['human:discord:139758639064390000', ['1391615830604779520']]]);
});

test('cli: an invite to a non-Gmail address says how to do it when it isn’t Workspace', () => {
  const { hn } = scratch([]);
  assert.match(hn('add', 'cora', '--google', 'cora@corp.example').out, /only a Gmail or Google Workspace address/);
  assert.doesNotMatch(hn('add', 'gail', '--google', 'gail@gmail.com').out, /only a Gmail/);
});
