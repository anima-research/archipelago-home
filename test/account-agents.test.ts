/**
 * A ticket holder makes invites for their agents on /account: the ticket's
 * reach and budget (as when the ticket site asks), listed for the ticket site
 * too, withdrawn while unused. An account without a ticket gets none.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HomeNode } from '../src/server.js';
import type { EmailSender } from '../src/email.js';
import { emailKey } from '../src/google.js';

const TOKEN = 'tickets-token-test-0123456789abcdef';
let node: HomeNode;
let base: string;
let ipSeq = 0;
const outbox: Array<{ to: string; text: string }> = [];
const sender: EmailSender = { async send(to, _subject, text) { outbox.push({ to, text }); } };
const lastCode = (to: string) => /\b(\d{6})\b/.exec([...outbox].reverse().find((m) => emailKey(m.to) === emailKey(to))!.text)![1]!;

before(async () => {
  const dir = mkdtempSync(join(tmpdir(), 'hn-agents-'));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({ principals: [] }));
  writeFileSync(join(dir, 'audiences.json'), JSON.stringify({
    members: { redirect: 'https://members.test/auth', requiredScopes: ['members:member'] },
    tickets: { redirect: 'https://tickets.test/agents' },
  }));
  writeFileSync(join(dir, 'ticket-defaults.json'), JSON.stringify({
    audiences: ['members', 'tickets'], scopes: ['members:member'],
    allowed: { audiences: ['members', 'tickets'], scopes: ['members:member'] }, invites: { active: 2, lifetime: 3 },
  }));
  writeFileSync(join(dir, 'invite-policy.json'), JSON.stringify({
    console: { requiredScopes: ['members:member'] }, primaryAudience: 'members',
    scopes: { 'members:member': ['delegable', 'baseline'] },
    audiences: [{ audience: 'members', always: true }, { audience: 'tickets', always: true }],
  }));
  node = new HomeNode(
    { iss: 'id.test', publicUrl: 'https://id.test', bind: '127.0.0.1', port: 0, dataDir: dir, configDir: dir, ticketsToken: TOKEN },
    { email: sender },
  );
  base = `http://127.0.0.1:${await node.start()}`;
});
after(() => node.stop());

const hdrs = (extra: Record<string, string> = {}) => ({ 'x-real-ip': `10.3.${ipSeq >> 8 & 255}.${ipSeq++ & 255}`, ...extra });
async function post(path: string, body: unknown, token?: string) {
  const r = await fetch(base + path, { method: 'POST', body: JSON.stringify(body), headers: hdrs({ 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) }) });
  return { status: r.status, body: (await r.json()) as Record<string, any> };
}
async function accountToken(email: string): Promise<string> {
  const page = await (await fetch(`${base}/login?audience=account`, { headers: hdrs() })).text();
  const state = /"state":"([^"]+)"/.exec(page)![1]!;
  await post('/login/email/begin', { state, email });
  const r = await post('/login/email/finish', { state, email, code: lastCode(email) });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return /#token=(.+)$/.exec(r.body.redirect)![1]!;
}

test('a ticket holder makes, sees and withdraws invites for their agents on /account, within the ticket’s budget', async () => {
  assert.equal((await post('/tickets', { email: 'holder@example.org', ref: 'tickets:human:1' }, TOKEN)).status, 201);
  // The email from the ticket site sends people to /login?audience=account: a first sign-in there makes the account.
  const tok = await accountToken('holder@example.org');
  const me = await (await fetch(`${base}/account/me`, { headers: hdrs({ authorization: `Bearer ${tok}` }) })).json();
  assert.equal(me.agentInvites, true);

  const a = await post('/account/agents', { agentName: 'Fable' }, tok);
  assert.equal(a.status, 200, JSON.stringify(a.body));
  assert.match(a.body.code, /\S/);
  const inv = node.invites.all().find((i) => i.code === a.body.code)!;
  assert.deepEqual([...inv.audiences!].sort(), ['members', 'tickets'], "the ticket's reach");
  assert.equal(inv.label, 'Fable');

  // The ticket site sees it among the holder's invites (it checks an agent redeemed one of them).
  const listed = await fetch(`${base}/tickets/invites?email=holder%40example.org`, { headers: hdrs({ authorization: `Bearer ${TOKEN}` }) });
  assert.ok(((await listed.json()) as any).invites.some((i: any) => i.code === a.body.code));
  // ...and, from the code alone, whose ticket it is (an agent registering there quotes only the code).
  const owner = await fetch(`${base}/tickets/invites/${encodeURIComponent(a.body.code)}`, { headers: hdrs({ authorization: `Bearer ${TOKEN}` }) });
  assert.deepEqual(await owner.json(), { email: 'holder@example.org', refs: ['tickets:human:1'] });
  assert.equal((await fetch(`${base}/tickets/invites/nope`, { headers: hdrs({ authorization: `Bearer ${TOKEN}` }) })).status, 404);
  assert.equal((await fetch(`${base}/tickets/invites/${encodeURIComponent(a.body.code)}`, { headers: hdrs() })).status, 401);

  // Two waiting at once is the most; withdrawing one frees a place; three ever is the lifetime.
  const b = await post('/account/agents', {}, tok);
  assert.equal(b.status, 200);
  const c = await post('/account/agents', {}, tok);
  assert.equal(c.status, 409);
  assert.match(c.body.error, /most invites waiting/);
  assert.equal((await post('/account/agents/withdraw', { code: b.body.code }, tok)).status, 200);
  assert.equal((await post('/account/agents/withdraw', { code: b.body.code }, tok)).status, 404);
  const list = await post('/account/agents/list', {}, tok);
  assert.deepEqual(list.body.invites.map((i: any) => i.code), [a.body.code]);
  assert.equal((await post('/account/agents', {}, tok)).status, 200);
  const d = await post('/account/agents', {}, tok);
  assert.equal(d.status, 409);
  assert.match(d.body.error, /all the invites it can/);
});

test('an account without a ticket has no agent invites here', async () => {
  // A second mailbox that held a ticket, refunded before: the account stays, the invites go.
  assert.equal((await post('/tickets', { email: 'later@example.org', ref: 'tickets:human:2' }, TOKEN)).status, 201);
  const tok = await accountToken('later@example.org');
  await fetch(`${base}/tickets/later%40example.org`, { method: 'DELETE', headers: hdrs({ authorization: `Bearer ${TOKEN}` }) });
  const me = await (await fetch(`${base}/account/me`, { headers: hdrs({ authorization: `Bearer ${tok}` }) })).json();
  assert.equal(me.agentInvites, false);
  assert.equal((await post('/account/agents', {}, tok)).status, 404);
  assert.equal((await post('/account/agents/list', {}, tok)).status, 404);
});
