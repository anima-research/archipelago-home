/**
 * The node's pages for people (home, enroll, the old console address) and the
 * account page's agent invites and admin tools.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HomeNode } from '../src/server.js';
import { hashPassword } from '../src/accounts.js';

let node: HomeNode;
let base: string;
let dir: string;
let ipSeq = 0;

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'hn-pages-'));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({ principals: [] }));
  writeFileSync(join(dir, 'site.json'), JSON.stringify({ name: 'Test Conference', description: 'Sign in for the test conference.' }));
  writeFileSync(join(dir, 'audiences.json'), JSON.stringify({
    tickets: { redirect: 'https://tickets.test/signin', name: 'Tickets', description: 'Your ticket', url: 'https://tickets.test' },
    hidden: { redirect: 'https://hidden.test/auth', signup: { scopes: [] }, custom: 'kept' },
  }));
  // invites from the account page only for admins, as on the coev node
  writeFileSync(join(dir, 'invite-policy.json'), JSON.stringify({
    console: { requiredScopes: ['hn:admin'] }, primaryAudience: 'tickets',
    scopes: { 'members:member': ['delegable', 'baseline'] }, audiences: [{ audience: 'tickets', always: true }],
  }));
  node = new HomeNode({ iss: 'id.test', publicUrl: 'https://id.test', bind: '127.0.0.1', port: 0, dataDir: dir, configDir: dir }, {});
  base = `http://127.0.0.1:${await node.start()}`;
  await node.accounts.add({ sub: 'human:local:ada', username: 'ada', password: await hashPassword('ada password 1'), scopes: ['hn:admin', 'members:member'], createdAt: '2026-11-01T00:00:00Z' });
  await node.accounts.add({ sub: 'human:local:bo', username: 'bo', password: await hashPassword('bo password 1'), scopes: ['members:member'], createdAt: '2026-11-02T00:00:00Z' });
});
after(() => node.stop());

const hdrs = (extra: Record<string, string> = {}) => ({ 'x-real-ip': `10.4.${ipSeq >> 8 & 255}.${ipSeq++ & 255}`, ...extra });
const get = async (path: string) => {
  const r = await fetch(base + path, { headers: hdrs(), redirect: 'manual' });
  return { status: r.status, text: await r.text() };
};
async function post(path: string, body: unknown, token?: string) {
  const r = await fetch(base + path, { method: 'POST', body: JSON.stringify(body), headers: hdrs({ 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) }) });
  return { status: r.status, body: (await r.json()) as Record<string, any> };
}
async function accountToken(username: string, password: string): Promise<string> {
  const page = (await get('/login?audience=account')).text;
  const state = /"state":"([^"]+)"/.exec(page)![1]!;
  const r = await post('/login/password', { state, username, password });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return /#token=(.+)$/.exec(r.body.redirect)![1]!;
}

test('the home page says what this is, offers signing in, lists named services, and keeps the key in the details', async () => {
  const r = await get('/');
  assert.equal(r.status, 200);
  assert.match(r.text, /<h1>Test Conference<\/h1>/);
  assert.match(r.text, /Sign in for the test conference\./);
  assert.match(r.text, /href="\/login\?audience=account">Sign in<\/a>/);
  assert.match(r.text, /What is Archipelago\?/);
  assert.match(r.text, /<b>Tickets<\/b>/);
  assert.doesNotMatch(r.text, /hidden\.test/, 'an audience without a name is not listed');
  const details = r.text.slice(r.text.indexOf('<details'));
  assert.ok(details.includes(node.issuer.id), 'the issuer key, in the technical details');
  assert.ok(!r.text.slice(0, r.text.indexOf('<details')).includes(node.issuer.id), 'and nowhere above them');
});

test('the enroll page says agents do it themselves; the console address points to the account', async () => {
  const en = await get('/enroll');
  assert.equal(en.status, 200);
  assert.match(en.text, /Enrolling is done by agents/);
  assert.match(en.text, /href="\/agents\.md"/);
  const c = await get('/console');
  assert.equal(c.status, 200);
  assert.match(c.text, /Agent invites are in your account now/);
  // the sign-in page names the service by its name
  assert.match((await get('/login?audience=tickets')).text, /to continue to <b>Tickets<\/b>/);
});

test('agent invites on the account page: only for accounts the console’s gate admits', async () => {
  const bo = await accountToken('bo', 'bo password 1');
  const me = await (await fetch(`${base}/account/me`, { headers: hdrs({ authorization: `Bearer ${bo}` }) })).json();
  assert.equal(me.invites, null, 'a member without hn:admin sees no invites here (the coev node: those come through the ticket site)');
  assert.equal(me.admin, false);
  assert.equal((await post('/account/invites', {}, bo)).status, 403);

  const ada = await accountToken('ada', 'ada password 1');
  const meA = await (await fetch(`${base}/account/me`, { headers: hdrs({ authorization: `Bearer ${ada}` }) })).json();
  assert.ok(meA.invites);
  const m = await post('/account/invites', { label: 'for Wren' }, ada);
  assert.equal(m.status, 200, JSON.stringify(m.body));
  const code = m.body.invite.code;
  assert.ok(node.invites.all().some((i) => i.code === code && i.sponsor === 'human:local:ada'));
  const list = await post('/account/invites/list', {}, ada);
  assert.deepEqual(list.body.invites.map((i: any) => [i.code, i.label, i.status]), [[code, 'for Wren', 'unclaimed']]);
  assert.equal((await post('/account/invites/withdraw', { code }, ada)).status, 200);
  assert.equal((await post('/account/invites/withdraw', { code }, ada)).status, 404);
});

test('admins edit audiences (with a backup each time), and nobody else can', async () => {
  const bo = await accountToken('bo', 'bo password 1');
  assert.equal((await post('/account/admin/audiences', {}, bo)).status, 403);
  assert.equal((await post('/account/admin/people', {}, bo)).status, 403);
  const ada = await accountToken('ada', 'ada password 1');
  const list = await post('/account/admin/audiences', {}, ada);
  assert.deepEqual(Object.keys(list.body.audiences).sort(), ['hidden', 'tickets']);

  const add = await post('/account/admin/audiences/save', { id: 'board', entry: { name: 'Board', redirect: 'https://board.test/auth', requiredScopes: ['members:member'] } }, ada);
  assert.equal(add.status, 200, JSON.stringify(add.body));
  const file = JSON.parse(readFileSync(join(dir, 'audiences.json'), 'utf8'));
  assert.deepEqual(file.board, { redirect: 'https://board.test/auth', requiredScopes: ['members:member'], name: 'Board' });
  assert.ok(readdirSync(dir).some((f) => f.startsWith('audiences.json.bak-')), 'the file as it was is kept');

  // editing keeps what the form doesn't show; clearing a field removes it
  assert.equal((await post('/account/admin/audiences/save', { id: 'hidden', entry: { redirect: 'https://hidden.test/back' } }, ada)).status, 200);
  assert.deepEqual(JSON.parse(readFileSync(join(dir, 'audiences.json'), 'utf8')).hidden, { redirect: 'https://hidden.test/back', signup: { scopes: [] }, custom: 'kept' });

  for (const [body, err] of [
    [{ id: 'x', entry: { redirect: 'http://evil.example/' } }, /https/],
    [{ id: 'account', entry: { redirect: 'https://a.test' } }, /node’s own/],
    [{ id: 'Bad Id', entry: { redirect: 'https://a.test' } }, /lowercase/],
    [{ id: 'y', entry: { redirect: 'https://y.test', requiredScopes: ['no spaces please'] } }, /scopes/],
  ] as const) {
    const r = await post('/account/admin/audiences/save', body, ada);
    assert.equal(r.status, 400);
    assert.match(r.body.error, err);
  }
  assert.equal((await post('/account/admin/audiences/remove', { id: 'board' }, ada)).status, 200);
  assert.equal(JSON.parse(readFileSync(join(dir, 'audiences.json'), 'utf8')).board, undefined);
  assert.ok(existsSync(join(dir, 'audiences.json')));
});

test('admins see people and agents, grant and withdraw scopes, disable and enable — never themselves out', async () => {
  const ada = await accountToken('ada', 'ada password 1');
  const people = (await post('/account/admin/people', {}, ada)).body.people;
  const bo = people.find((p: any) => p.sub === 'human:local:bo');
  assert.deepEqual([bo.name, bo.admin, bo.disabled, bo.scopes, bo.signIn], ['bo', false, false, ['members:member'], ['password']]);
  assert.equal(people.find((p: any) => p.sub === 'human:local:ada').admin, true);

  assert.equal((await post('/account/admin/people/set', { sub: 'human:local:bo', scopes: ['members:member', 'hn:admin'] }, ada)).status, 200);
  assert.deepEqual(node.accounts.bySub('human:local:bo')!.scopes, ['members:member', 'hn:admin']);
  assert.equal((await post('/account/admin/people/set', { sub: 'human:local:bo', scopes: ['members:member'] }, ada)).status, 200);
  assert.equal((await post('/account/admin/people/set', { sub: 'human:local:bo', disabled: true }, ada)).status, 200);
  assert.equal(node.accounts.bySub('human:local:bo')!.disabled, true);
  const page = (await get('/login?audience=account')).text;
  const refused = await post('/login/password', { state: /"state":"([^"]+)"/.exec(page)![1]!, username: 'bo', password: 'bo password 1' });
  assert.notEqual(refused.status, 200, 'a disabled account signs in no more');
  assert.equal((await post('/account/admin/people/set', { sub: 'human:local:bo', disabled: false }, ada)).status, 200);
  assert.equal(node.accounts.bySub('human:local:bo')!.disabled, undefined);

  for (const body of [{ sub: 'human:local:ada', disabled: true }, { sub: 'human:local:ada', scopes: ['members:member'] }]) {
    const r = await post('/account/admin/people/set', body, ada);
    assert.equal(r.status, 400);
    assert.match(r.body.error, /yourself|your own admin/);
  }
  assert.equal((await post('/account/admin/people/set', { sub: 'human:local:nobody', disabled: true }, ada)).status, 404);
  assert.deepEqual((await post('/account/admin/agents', {}, ada)).body, { agents: [] });
});
