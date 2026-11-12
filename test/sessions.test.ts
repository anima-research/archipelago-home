/**
 * Sign-in sessions: sign in once here, then the node's own account page opens
 * straight away and any other service is one click ("Continue as …"); a
 * disabled account, or signing out, ends it.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HomeNode } from '../src/server.js';
import { hashPassword } from '../src/accounts.js';
import { verifyToken } from '../src/token.js';

let node: HomeNode;
let base: string;
let dir: string;
let ipSeq = 0;

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'hn-sessions-'));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({ principals: [] }));
  writeFileSync(join(dir, 'audiences.json'), JSON.stringify({ tickets: { redirect: 'https://tickets.test/signin', name: 'Tickets' } }));
  node = new HomeNode({ iss: 'id.test', publicUrl: 'https://id.test', bind: '127.0.0.1', port: 0, dataDir: dir, configDir: dir }, {});
  base = `http://127.0.0.1:${await node.start()}`;
  await node.accounts.add({ sub: 'human:local:ada', username: 'ada', name: 'Ada', password: await hashPassword('ada password 1'), scopes: ['members:member'], createdAt: '' });
});
after(() => node.stop());

const hdrs = (extra: Record<string, string> = {}) => ({ 'x-real-ip': `10.5.${ipSeq >> 8 & 255}.${ipSeq++ & 255}`, ...extra });
const get = async (path: string, cookie = '') => {
  const r = await fetch(base + path, { headers: hdrs(cookie ? { cookie } : {}), redirect: 'manual' });
  return { status: r.status, location: r.headers.get('location'), text: await r.text() };
};
async function post(path: string, body: unknown, extra: Record<string, string> = {}) {
  const r = await fetch(base + path, { method: 'POST', body: JSON.stringify(body), headers: hdrs({ 'content-type': 'application/json', ...extra }) });
  return { status: r.status, setCookie: r.headers.getSetCookie(), body: (await r.json()) as Record<string, any> };
}
const stateOf = (html: string) => /"state":"([^"]+)"/.exec(html)![1]!;
const tokenIn = (redirect: string, aud: string) => {
  const v = verifyToken(/#token=(.+)$/.exec(redirect)![1]!, { issuerId: node.issuer.id, iss: 'id.test', aud });
  assert.ok(v.ok);
  return v.payload;
};
async function signInWithPassword(audience: string) {
  const r = await post('/login/password', { state: stateOf((await get(`/login?audience=${audience}`)).text), username: 'ada', password: 'ada password 1' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return r;
}

test('a sign-in starts a session: an HttpOnly cookie, stored only as a hash', async () => {
  const r = await signInWithPassword('tickets');
  const c = r.setCookie.find((x) => x.startsWith('hn_session='))!;
  assert.match(c, /; Path=\/; Max-Age=2592000; HttpOnly; SameSite=Lax; Secure$/);
  const value = c.split(';')[0]!.slice('hn_session='.length);
  assert.ok(value.length >= 40);
  const stored = readFileSync(join(dir, 'sessions.json'), 'utf8');
  assert.ok(!stored.includes(value), 'the cookie value is not stored');
  assert.equal(node.sessions.all().at(-1)!.sub, 'human:local:ada');
});

test('with a session: the account page opens straight away; another service is one click; "use another account" skips it', async () => {
  const r = await signInWithPassword('tickets');
  const cookie = r.setCookie.find((x) => x.startsWith('hn_session='))!.split(';')[0]!;
  // the node's own account page: straight in
  const acct = await get('/login?audience=account', cookie);
  assert.equal(acct.status, 302);
  assert.equal(tokenIn(acct.location!, 'account').sub, 'human:local:ada');
  // another service: "Continue as", one POST
  const page = await get('/login?audience=tickets', cookie);
  assert.equal(page.status, 200);
  assert.match(page.text, /Continue as Ada/);
  const cont = await post('/login/session', { state: stateOf(page.text) }, { cookie });
  assert.equal(cont.status, 200, JSON.stringify(cont.body));
  assert.ok(cont.body.redirect.startsWith('https://tickets.test/signin#token='));
  assert.equal(tokenIn(cont.body.redirect, 'tickets').sub, 'human:local:ada');
  // the state is spent, and without the cookie there's nothing to continue as
  assert.equal((await post('/login/session', { state: stateOf(page.text) }, { cookie })).status, 400);
  assert.equal((await post('/login/session', { state: stateOf((await get('/login?audience=tickets')).text) })).status, 401);
  assert.doesNotMatch((await get('/login?audience=tickets&switch=1', cookie)).text, /Continue as/);
  assert.equal((await get('/login?audience=account&switch=1', cookie)).status, 200);
});

test('a disabled account’s session stops working; signing out ends it', async () => {
  const r = await signInWithPassword('tickets');
  const cookie = r.setCookie.find((x) => x.startsWith('hn_session='))!.split(';')[0]!;
  node.accounts.update('human:local:ada', (a) => ({ ...a, disabled: true }));
  assert.equal((await get('/login?audience=account', cookie)).status, 200, 'no straight-in');
  const page = await get('/login?audience=tickets', cookie);
  assert.doesNotMatch(page.text, /Continue as/);
  assert.equal((await post('/login/session', { state: stateOf(page.text) }, { cookie })).status, 401);
  node.accounts.update('human:local:ada', (a) => { const { disabled: _d, ...rest } = a; return rest; });

  const acct = await get('/login?audience=account', cookie);
  const accountToken = /#token=(.+)$/.exec(acct.location!)![1]!;
  const out = await post('/account/signout', {}, { cookie, authorization: `Bearer ${accountToken}` });
  assert.equal(out.status, 200);
  assert.match(out.setCookie.find((x) => x.startsWith('hn_session='))!, /^hn_session=; Path=\/; Max-Age=0;/);
  assert.equal((await get('/login?audience=account', cookie)).status, 200, 'signed out: the sign-in page again');
});
