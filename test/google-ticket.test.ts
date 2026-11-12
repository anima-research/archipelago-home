/**
 * A ticket holder can start with Google: when Google vouches for the ticket's
 * address (Gmail, Workspace), the first Google sign-in makes the account and
 * claims the ticket, as a first email sign-in does. Anything else is refused
 * as before, and one address never ends up with two accounts.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HomeNode } from '../src/server.js';
import { verifyToken } from '../src/token.js';
import type { EmailSender } from '../src/email.js';
import { emailKey } from '../src/google.js';

const TOKEN = 'tickets-token-test-0123456789abcdef';
let node: HomeNode;
let base: string;
let ipSeq = 0;
let googleUser: Record<string, unknown> = {};
const outbox: Array<{ to: string; text: string }> = [];
const sender: EmailSender = { async send(to, _subject, text) { outbox.push({ to, text }); } };
const lastCode = (to: string) => /\b(\d{6})\b/.exec([...outbox].reverse().find((m) => emailKey(m.to) === emailKey(to))!.text)![1]!;
const b64j = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');

const fakeGoogle = (async (input: string | URL | Request) => {
  if (String(input) !== 'https://oauth2.googleapis.com/token') return new Response('nope', { status: 500 });
  const claims = { iss: 'https://accounts.google.com', aud: 'gcid', exp: Math.floor(Date.now() / 1000) + 300, ...googleUser };
  return new Response(JSON.stringify({ access_token: 'ga', id_token: `${b64j({ alg: 'RS256' })}.${b64j(claims)}.sig` }), { status: 200 });
}) as typeof fetch;

before(async () => {
  const dir = mkdtempSync(join(tmpdir(), 'hn-gticket-'));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({ principals: [] }));
  writeFileSync(join(dir, 'audiences.json'), JSON.stringify({ members: { redirect: 'https://members.test/auth', requiredScopes: ['members:member'] } }));
  writeFileSync(join(dir, 'ticket-defaults.json'), JSON.stringify({ audiences: ['members'], scopes: ['members:member'], allowed: { audiences: ['members'], scopes: ['members:member'] } }));
  node = new HomeNode(
    { iss: 'id.test', publicUrl: 'https://id.test', bind: '127.0.0.1', port: 0, dataDir: dir, configDir: dir, ticketsToken: TOKEN, googleClientId: 'gcid', googleClientSecret: 'gsecret' },
    { email: sender, fetchImpl: fakeGoogle },
  );
  base = `http://127.0.0.1:${await node.start()}`;
});
after(() => node.stop());

const hdrs = (extra: Record<string, string> = {}) => ({ 'x-real-ip': `10.2.${ipSeq >> 8 & 255}.${ipSeq++ & 255}`, ...extra });
async function get(path: string) {
  const r = await fetch(base + path, { headers: hdrs(), redirect: 'manual' });
  return { status: r.status, location: r.headers.get('location'), text: await r.text() };
}
async function post(path: string, body: unknown, token?: string) {
  const r = await fetch(base + path, { method: 'POST', body: JSON.stringify(body), headers: hdrs({ 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) }) });
  return { status: r.status, body: (await r.json()) as Record<string, any> };
}
const addTicket = (email: string, ref: string, name?: string) => post('/tickets', { email, ref, ...(name ? { name } : {}) }, TOKEN);
async function googleLogin(audience: string) {
  const start = await get(`/login?audience=${audience}&via=google`);
  assert.equal(start.status, 302);
  return get(`/oauth/google/callback?state=${new URL(start.location!).searchParams.get('state')}&code=x`);
}
async function emailLogin(email: string, audience: string) {
  const state = /"state":"([^"]+)"/.exec((await get(`/login?audience=${audience}`)).text)![1]!;
  await post('/login/email/begin', { state, email });
  return post('/login/email/finish', { state, email, code: lastCode(email) });
}
const subIn = (redirect: string) => {
  const v = verifyToken(/#token=(.+)$/.exec(redirect)![1]!, { issuerId: node.issuer.id, iss: 'id.test', aud: 'members' });
  assert.ok(v.ok);
  return v.payload.sub;
};

test('a Gmail ticket holder starts with Google: the account is made, the ticket claimed, and email sign-in finds the same account', async () => {
  assert.equal((await addTicket('Ada.Holder@gmail.com', 'tickets:human:1', 'Ada Holder')).status, 201);
  googleUser = { sub: 'g-ada', email: 'adaholder@gmail.com', email_verified: true, name: 'Ada (Google)' };
  const r = await googleLogin('members');
  assert.equal(r.status, 302, r.text);
  const sub = subIn(r.location!);
  assert.match(sub, /^human:email:/);
  const acct = node.accounts.bySub(sub)!;
  assert.equal(acct.google?.sub, 'g-ada');
  assert.equal(acct.email?.address, 'adaholder@gmail.com');
  assert.equal(acct.name, 'Ada Holder', "the ticket's name");
  assert.deepEqual(acct.ticket?.audiences, ['members']);
  assert.equal(node.tickets.byEmail('ada.holder@gmail.com')!.claimedBy, sub);

  // Google again, then email: the same account both times.
  assert.equal(subIn((await googleLogin('members')).location!), sub);
  const byEmail = await emailLogin('ada.holder@gmail.com', 'members');
  assert.equal(byEmail.status, 200, JSON.stringify(byEmail.body));
  assert.equal(subIn(byEmail.body.redirect), sub);
  assert.equal(node.accounts.all().filter((a) => a.email && emailKey(a.email.address) === emailKey('ada.holder@gmail.com')).length, 1);
});

test('a Workspace address counts; one Google does not vouch for is refused and the ticket stays unclaimed', async () => {
  await addTicket('sam@coev.example', 'tickets:human:2');
  googleUser = { sub: 'g-sam', email: 'sam@coev.example', email_verified: true, hd: 'coev.example' };
  assert.equal((await googleLogin('members')).status, 302);
  assert.ok(node.tickets.byEmail('sam@coev.example')!.claimedBy);

  await addTicket('pat@elsewhere.example', 'tickets:human:3');
  googleUser = { sub: 'g-pat', email: 'pat@elsewhere.example', email_verified: true };
  const r = await googleLogin('members');
  assert.equal(r.status, 403);
  assert.match(r.text, /isn’t linked to an account here/);
  assert.equal(node.tickets.byEmail('pat@elsewhere.example')!.claimedBy, undefined);
});

test('someone who already signed in by email gets no second account from Google: they link it on their account page', async () => {
  await addTicket('bo@gmail.com', 'tickets:human:4');
  const first = await emailLogin('bo@gmail.com', 'members');
  assert.equal(first.status, 200);
  googleUser = { sub: 'g-bo', email: 'bo@gmail.com', email_verified: true };
  assert.equal((await googleLogin('members')).status, 403);
  assert.equal(node.accounts.byGoogle('g-bo'), undefined);
  assert.equal(node.accounts.all().filter((a) => a.email && emailKey(a.email.address) === emailKey('bo@gmail.com')).length, 1);
});
