/**
 * Ticket holders sign in by email: a real HomeNode on a random port, the
 * mail caught at the EmailSender seam, tickets arriving through the ticket
 * site's API.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HomeNode, type ServerConfig } from '../src/server.js';
import { verifyToken, type Aid1Payload } from '../src/token.js';
import { hashPassword } from '../src/accounts.js';
import { generateKey } from '../src/keys.js';
import { makeEnrollRequest } from '../src/statements.js';
import { EMAIL_SENT_MESSAGE } from '../src/human.js';
import type { EmailSender } from '../src/email.js';
import { emailKey } from '../src/google.js';

const TOKEN = 'tickets-token-test-0123456789abcdef'; // ≥ 32 characters
const DEFAULTS = { audiences: ['members'], scopes: ['members:member'], allowed: { audiences: ['members', 'gate'], scopes: ['members:member', 'extra:use'] } };
let node: HomeNode;
let base: string;
let ipSeq = 0;
/** Every message the node sent, newest last. */
const outbox: Array<{ to: string; subject: string; text: string }> = [];
const sender: EmailSender = { async send(to, subject, text) { outbox.push({ to, subject, text }); } };
/** The code last sent to this mailbox (however the address was spelled). */
const lastCode = (to: string) => /\b(\d{6})\b/.exec([...outbox].reverse().find((m) => emailKey(m.to) === emailKey(to))!.text)![1]!;

function makeNode(extra: Partial<ServerConfig> = {}, opts: { email?: EmailSender | null; defaults?: unknown } = {}): HomeNode {
  const dir = mkdtempSync(join(tmpdir(), 'hn-email-'));
  writeFileSync(join(dir, 'roles.json'), JSON.stringify({ guildId: 'g1', map: {} }));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({ principals: [] }));
  writeFileSync(join(dir, 'audiences.json'), JSON.stringify({
    members: { redirect: 'https://members.test/auth', requiredScopes: ['members:member'] },
    eidoverse: { redirect: 'https://worlds.test/auth', requiredScopes: ['worlds:join'] },
    gate: { redirect: 'https://gate.test/auth' }, // no requiredScopes: takes any grant — a ticket must not open it
  }));
  if (opts.defaults !== null) writeFileSync(join(dir, 'ticket-defaults.json'), JSON.stringify(opts.defaults ?? DEFAULTS));
  // the invite policy: what a ticket holder may pass to an agent, and where it may go
  writeFileSync(join(dir, 'invite-policy.json'), JSON.stringify({
    console: { requiredScopes: [] },
    scopes: { 'members:member': ['delegable'], 'extra:use': ['delegable'], 'docs:use': ['baseline'] },
    audiences: [{ audience: 'members', when: ['members:*'] }, { audience: 'gate', when: ['extra:use'] }],
  }));
  return new HomeNode(
    { iss: 'id.test', publicUrl: 'https://id.test', bind: '127.0.0.1', port: 0, dataDir: dir, configDir: dir, ticketsToken: TOKEN, ...extra },
    { ...(opts.email === null ? {} : { email: opts.email ?? sender }) },
  );
}

before(async () => {
  node = makeNode();
  base = `http://127.0.0.1:${await node.start()}`;
});
after(() => node.stop());

const hdrs = (extra: Record<string, string> = {}) => ({ 'x-real-ip': `10.1.${ipSeq >> 8 & 255}.${ipSeq++ & 255}`, ...extra });
async function get(path: string, b = base, extra: Record<string, string> = {}) {
  const r = await fetch(b + path, { headers: hdrs(extra), redirect: 'manual' });
  return { status: r.status, text: await r.text() };
}
async function post(path: string, body: unknown, token?: string, extra: Record<string, string> = {}, b = base) {
  const r = await fetch(b + path, {
    method: 'POST', body: JSON.stringify(body),
    headers: hdrs({ 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}), ...extra }),
  });
  return { status: r.status, body: (await r.json()) as Record<string, any> };
}
async function loginState(audience: string, b = base): Promise<string> {
  const r = await get(`/login?audience=${audience}`, b);
  assert.equal(r.status, 200);
  return /"state":"([^"]+)"/.exec(r.text)![1]!;
}
function tokenFrom(redirect: string, aud: string, n = node): Aid1Payload {
  const tok = /#token=(.+)$/.exec(redirect)![1]!;
  const v = verifyToken(tok, { issuerId: n.issuer.id, iss: 'id.test', aud });
  assert.ok(v.ok, !v.ok ? v.reason : '');
  return v.payload;
}
const rawToken = (redirect: string) => /#token=(.+)$/.exec(redirect)![1]!;
/** The ticket site's call. */
async function api(method: 'POST' | 'GET' | 'DELETE', path: string, body?: unknown, opts: { token?: string | null; b?: string } = {}) {
  const r = await fetch((opts.b ?? base) + path, {
    method, ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    headers: hdrs({ 'content-type': 'application/json', ...(opts.token === null ? {} : { authorization: `Bearer ${opts.token ?? TOKEN}` }) }),
  });
  const text = await r.text();
  return { status: r.status, body: (text ? JSON.parse(text) : null) as Record<string, any> | null };
}
const addTicket = (email: string, ref: string, extra: Record<string, unknown> = {}, b?: string) => api('POST', '/tickets', { email, ref, ...extra }, { b });
async function emailLogin(email: string, audience: string, code?: string) {
  const state = await loginState(audience);
  const begin = await post('/login/email/begin', { state, email });
  assert.equal(begin.status, 200, JSON.stringify(begin.body));
  return post('/login/email/finish', { state, email, code: code ?? lastCode(email) });
}

test('tickets API: bearer-gated; POST makes a ticket with the configured defaults (201), knows a ref again (200), keeps the first ticket per mailbox; GET and DELETE', async () => {
  // no token, a wrong one, the wrong shape: 401, nothing made
  for (const token of [null, 'nope', `${TOKEN}x`, TOKEN.slice(0, -1)]) {
    assert.equal((await api('POST', '/tickets', { email: 'x@y.co', ref: 'r' }, { token })).status, 401, String(token));
  }
  assert.equal((await api('GET', '/tickets/x%40y.co', undefined, { token: null })).status, 401);
  assert.equal(node.tickets.byEmail('x@y.co'), undefined);
  // the scheme word is case-insensitive
  const lower = await fetch(base + '/tickets/x%40y.co', { headers: hdrs({ authorization: `bearer ${TOKEN}` }) });
  assert.equal(lower.status, 200);

  const made = await addTicket('Pat.Buyer+x@gmail.com', 'tickets:human:1', { note: 'front\u0000 row', name: 'Pat\nBuyer' });
  assert.equal(made.status, 201, JSON.stringify(made.body));
  assert.equal(made.body!.created, true);
  assert.equal(made.body!.ticket.note, undefined); // the view keeps the note to the operator
  const t = node.tickets.byEmail('patbuyer@gmail.com')!;
  assert.equal(t.email, 'Pat.Buyer+x@gmail.com');
  assert.equal(t.source, 'api:tickets:human:1');
  assert.equal(t.note, 'front row'); // control characters stripped
  assert.equal(t.name, 'PatBuyer');
  assert.deepEqual(t.audiences, ['members']);
  assert.deepEqual(t.scopes, ['members:member']);
  // only what ticket-defaults.json allows, never this node's own audiences, never an unknown one, never nothing
  for (const [grant, why] of [
    [{ audiences: ['console'] }, /this node’s own/], [{ audiences: ['account'] }, /this node’s own/],
    [{ audiences: ['eidoverse'] }, /not one a ticket may carry/], [{ audiences: ['nowhere'] }, /not one a ticket may carry/],
    [{ scopes: ['worlds:join'] }, /scope "worlds:join"/], [{ scopes: ['board:write'] }, /scope "board:write"/],
    [{ audiences: [] }, /at least one audience/], [{ audiences: ['members\u0000'] }, /not one a ticket may carry/],
  ] as Array<[Record<string, unknown>, RegExp]>) {
    const r = await addTicket('greedy@example.org', 'tickets:human:greedy', grant);
    assert.equal(r.status, 400, JSON.stringify(grant));
    assert.match(r.body!.error, why);
  }
  assert.equal(node.tickets.byEmail('greedy@example.org'), undefined);
  // the same ref again (a retry): 200, the same entry
  const again = await addTicket('pat.buyer@gmail.com', 'tickets:human:1');
  assert.equal(again.status, 200);
  assert.deepEqual(again.body, { ticket: made.body!.ticket, created: false });
  // the same mailbox with a new ref (a second purchase): 200, the first ticket stands, the ref is recorded, the grant widens
  const second = await addTicket('patbuyer@googlemail.com', 'tickets:human:2', { audiences: ['members', 'gate'], scopes: ['members:member', 'extra:use'] });
  assert.equal(second.status, 200);
  assert.equal(second.body!.ticket.source, 'api:tickets:human:1');
  assert.deepEqual(second.body!.ticket.refs, ['tickets:human:2']);
  assert.deepEqual(second.body!.ticket.audiences, ['members', 'gate']);
  assert.deepEqual(second.body!.ticket.scopes, ['members:member', 'extra:use']);
  // (narrowed back for the rest of the tests — a refund + new purchase, below, does the same)
  node.tickets.remove('patbuyer@gmail.com');
  assert.equal((await addTicket('patbuyer@gmail.com', 'tickets:human:1')).status, 410); // that ref is spent
  assert.equal((await addTicket('Pat.Buyer+x@gmail.com', 'tickets:human:1b', { name: 'Pat Buyer' })).status, 201);
  assert.equal(node.tickets.byEmail('patbuyer@gmail.com')!.addedAt !== t.addedAt, true);
  assert.equal((await addTicket('other@example.org', 'tickets:human:1b')).body!.ticket.email, 'Pat.Buyer+x@gmail.com'); // that ref is spoken for
  assert.equal(node.tickets.all().length, 1);
  // its own grant
  const own = await addTicket('vip@example.org', 'tickets:human:3', { scopes: ['members:member', 'extra:use'], audiences: ['members', 'gate'] });
  assert.equal(own.status, 201);
  assert.deepEqual(node.tickets.byEmail('vip@example.org')!.audiences, ['members', 'gate']);
  // bad input
  assert.equal((await addTicket('not-an-address', 'r')).status, 400);
  assert.equal((await api('POST', '/tickets', { email: 'a@b.co' })).status, 400);
  assert.equal((await addTicket('a@b.co', 'r', { scopes: 'members:member' })).status, 400);
  assert.equal((await api('POST', '/tickets', undefined)).status, 400);
  // GET: held or not, and who took it up
  assert.deepEqual((await api('GET', '/tickets/' + encodeURIComponent('pat.buyer@gmail.com'))).body, { held: true, addedAt: node.tickets.byEmail('patbuyer@gmail.com')!.addedAt });
  assert.deepEqual((await api('GET', '/tickets/nobody%40example.org')).body, { held: false });
  assert.equal((await api('GET', '/tickets/nope')).status, 400);
  assert.equal((await api('GET', '/tickets/%E0%A4%A')).status, 400);
  // DELETE: gone for future sign-ups; 404 when absent
  assert.equal((await addTicket('gone@example.org', 'tickets:human:4')).status, 201);
  assert.equal((await api('DELETE', '/tickets/gone%40example.org')).status, 204);
  assert.equal(node.tickets.byEmail('gone@example.org'), undefined);
  assert.equal((await api('DELETE', '/tickets/gone%40example.org')).status, 404);
  assert.equal((await api('DELETE', '/tickets/nope')).status, 400);
  assert.equal((await addTicket('gone@example.org', 'tickets:human:4')).status, 410); // a redelivery after the refund makes nothing
  assert.equal(node.tickets.byEmail('gone@example.org'), undefined);
  outbox.length = 0;
  const state = await loginState('members');
  assert.equal((await post('/login/email/begin', { state, email: 'gone@example.org' })).status, 200);
  assert.equal(outbox.length, 0); // no code for a removed ticket
});

test('HN_TICKETS_TOKEN shorter than 32 characters is refused at startup', () => {
  assert.throws(() => makeNode({ ticketsToken: 'short' }), /at least 32/);
});

test('begin: the same answer whether or not the address holds a ticket; a code goes out only to a holder', async () => {
  outbox.length = 0;
  const state = await loginState('members');
  const unknown = await post('/login/email/begin', { state, email: 'stranger@example.org' });
  assert.deepEqual(unknown, { status: 200, body: { ok: true, message: EMAIL_SENT_MESSAGE } });
  assert.equal(outbox.length, 0);
  // a guess against it is answered exactly as a wrong guess against a holder's code
  const guess = await post('/login/email/finish', { state, email: 'stranger@example.org', code: '000000' });
  const holder = await post('/login/email/begin', { state, email: 'pat.buyer@gmail.com' });
  assert.deepEqual(holder, unknown); // byte for byte the same
  const wrong = await post('/login/email/finish', { state, email: 'pat.buyer@gmail.com', code: '000000' });
  assert.deepEqual(guess, wrong);
  assert.deepEqual(guess, { status: 401, body: { error: 'wrong or expired code' } });
  // …and an address nobody ever asked a code for
  assert.deepEqual(await post('/login/email/finish', { state, email: 'never@example.org', code: '000000' }), guess);
  await new Promise((r) => setImmediate(r)); // the mail goes out after the answer
  assert.equal(outbox.length, 1);
  assert.equal(outbox[0]!.to, 'Pat.Buyer+x@gmail.com'); // the STORED spelling, not the typed one
  assert.match(outbox[0]!.text, /^Your sign-in code is \d{6}\. It expires in 10 minutes\. If you didn't request this, ignore it\.$/);
  assert.match(outbox[0]!.subject, /\d{6}/);
  // malformed input, dead state
  assert.equal((await post('/login/email/begin', { state, email: 'not-an-address' })).status, 400);
  assert.equal((await post('/login/email/begin', { state, email: '\u212Aim@example.org' })).status, 400); // a look-alike script
  assert.equal((await post('/login/email/begin', { state: 'nope', email: 'pat.buyer@gmail.com' })).status, 400);
  // asking again while a code is pending re-sends THAT code: no new budget, no knocking out the live one
  await addTicket('Re.Send@example.org', 'tickets:human:resend');
  assert.equal((await post('/login/email/begin', { state, email: 're.send@example.org' })).status, 200);
  await new Promise((r) => setImmediate(r));
  const before = lastCode('Re.Send@example.org');
  assert.equal((await post('/login/email/finish', { state, email: 're.send@example.org', code: '000000' })).status, 401);
  assert.equal((await post('/login/email/begin', { state, email: 'RE.SEND@example.org' })).status, 200);
  await new Promise((r) => setImmediate(r));
  assert.equal(outbox.filter((m) => m.to === 'Re.Send@example.org').length, 2);
  assert.equal(lastCode('Re.Send@example.org'), before);
  for (let i = 0; i < 3; i++) assert.equal((await post('/login/email/finish', { state, email: 're.send@example.org', code: '000000' })).status, 401);
  // the fifth wrong try — the one before was kept across the re-send — spends it
  assert.equal((await post('/login/email/finish', { state, email: 're.send@example.org', code: '000000' })).body.restart, true);
  assert.equal((await post('/login/email/finish', { state, email: 're.send@example.org', code: before })).status, 401);
});

test('finish: five wrong codes spend it (holder and stranger alike); the right code makes a human:email: account, claims the ticket and signs in — for the ticket’s audiences only', async () => {
  const state = await loginState('members');
  // the previous test left one wrong try on the holder's live code; a stranger's decoy runs the same course
  await post('/login/email/begin', { state, email: 'pat.buyer@gmail.com' });
  await post('/login/email/begin', { state, email: 'stranger2@example.org' });
  const code = lastCode('Pat.Buyer+x@gmail.com');
  for (let i = 0; i < 4; i++) {
    const r = await post('/login/email/finish', { state, email: 'stranger2@example.org', code: '000000' });
    assert.equal(r.status, 401);
    assert.equal(r.body.restart, undefined);
  }
  for (let i = 0; i < 3; i++) assert.equal((await post('/login/email/finish', { state, email: 'pat.buyer@gmail.com', code: '000000' })).status, 401);
  const fifth = await post('/login/email/finish', { state, email: 'pat.buyer@gmail.com', code: '000000' });
  assert.deepEqual(fifth, await post('/login/email/finish', { state, email: 'stranger2@example.org', code: '000000' }));
  assert.equal(fifth.status, 401);
  assert.equal(fifth.body.restart, true);
  const spent = await post('/login/email/finish', { state, email: 'pat.buyer@gmail.com', code });
  assert.deepEqual(spent, { status: 401, body: { error: 'wrong or expired code' } }); // the right code no longer counts
  assert.equal(node.accounts.byEmail('pat.buyer@gmail.com'), undefined);

  // a fresh code: in — the row carries the ticket's spelling of the address and the holder's name
  const done = await emailLogin('Pat.Buyer@gmail.com', 'members');
  assert.equal(done.status, 200, JSON.stringify(done.body));
  const p = tokenFrom(done.body.redirect, 'members');
  assert.match(p.sub, /^human:email:[A-Za-z0-9_-]{12}$/);
  assert.equal(p.kind, 'human');
  assert.equal(p.name, 'Pat Buyer');
  assert.deepEqual(p.scopes, ['members:member']);
  assert.ok(p.jti && p.exp - p.iat === 600);
  const row = node.accounts.bySub(p.sub)!;
  assert.equal(row.email!.address, 'Pat.Buyer+x@gmail.com');
  assert.ok(row.email!.verifiedAt);
  assert.deepEqual(row.ticket!.audiences, ['members']);
  assert.equal(row.ticket!.source, 'api:tickets:human:1b');
  assert.equal(row.scopes, undefined); // the grant lives on the ticket snapshot, audience-bound
  assert.equal(node.tickets.byEmail('patbuyer@gmail.com')!.claimedBy, p.sub);
  assert.deepEqual((await api('GET', '/tickets/patbuyer%40gmail.com')).body, { held: true, addedAt: node.tickets.byEmail('patbuyer@gmail.com')!.addedAt, claimedBy: p.sub });
  // the code is single-use
  assert.equal((await post('/login/email/finish', { state, email: 'Pat.Buyer@gmail.com', code: lastCode('Pat.Buyer+x@gmail.com') })).status, 401);
  // the ticket's scopes count for its audiences only
  const elsewhere = await emailLogin('pat.buyer@gmail.com', 'gate');
  assert.equal(elsewhere.status, 403);
  assert.equal((await emailLogin('pat.buyer@gmail.com', 'eidoverse')).status, 403);
  // sign-in settings open
  const acct = await emailLogin('pat.buyer@gmail.com', 'account');
  assert.equal(acct.status, 200);
  const me = JSON.parse((await get('/account/me', base, { authorization: `Bearer ${rawToken(acct.body.redirect)}` })).text);
  assert.deepEqual(me.email, { address: 'P***@gmail.com', since: row.email!.verifiedAt, canUnlink: false });
  assert.deepEqual(me.ticket, { since: row.ticket!.claimedAt, audiences: ['members'], scopes: ['members:member'] });
  assert.equal(me.canLinkEmail, false);
  assert.equal(me.hasPassword, false);
  // the anchor can't be removed
  const un = await post('/account/email/unlink', {}, rawToken(acct.body.redirect));
  assert.equal(un.status, 400);
  assert.match(un.body.error, /IS your email identity/);
  // the name is theirs to set (never the address)
  assert.equal(me.nameEditable, true);
  assert.equal((await post('/account/name', { name: 'pat@x.y' }, rawToken(acct.body.redirect))).status, 400);
  assert.equal((await post('/account/name', { name: 'admin' }, rawToken(acct.body.redirect))).status, 400);
  const named = await post('/account/name', { name: 'Patricia' }, rawToken(acct.body.redirect));
  assert.equal(named.status, 200, JSON.stringify(named.body));
  assert.equal(named.body.name, 'Patricia');
  assert.equal(tokenFrom((await emailLogin('pat.buyer@gmail.com', 'members')).body.redirect, 'members').name, 'Patricia');
});

test('a ticket without a name signs in as "Ticket holder" — the address never becomes a name', async () => {
  await addTicket('anon@example.org', 'tickets:human:anon');
  const r = await emailLogin('anon@example.org', 'members');
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(tokenFrom(r.body.redirect, 'members').name, 'Ticket holder');
});

test('ten wrong codes in a day lock the address out of email sign-in, begin and finish alike', async () => {
  await addTicket('locked@example.org', 'tickets:human:locked');
  const state = await loginState('members');
  await post('/login/email/begin', { state, email: 'locked@example.org' });
  for (let i = 0; i < 10; i++) {
    if (i === 5) await post('/login/email/begin', { state, email: 'locked@example.org' }); // a fresh code after the first was spent
    assert.equal((await post('/login/email/finish', { state, email: 'locked@example.org', code: '000000' })).status, 401, String(i));
  }
  const right = lastCode('locked@example.org');
  const fin = await post('/login/email/finish', { state, email: 'locked@example.org', code: right });
  assert.equal(fin.status, 429);
  assert.match(fin.body.error, /try again tomorrow/);
  assert.equal((await post('/login/email/begin', { state, email: 'Locked@example.org' })).status, 429);
  assert.equal(node.accounts.byEmail('locked@example.org'), undefined);
});

test('a second sign-up with the same mailbox is the same account; a refund takes the grant back, a new purchase gives it back; a second purchase widens it on the account', async () => {
  const first = node.accounts.byEmail('pat.buyer@gmail.com')!;
  const again = await emailLogin('PAT.BUYER+other@gmail.com', 'members');
  assert.equal(again.status, 200, JSON.stringify(again.body));
  assert.equal(tokenFrom(again.body.redirect, 'members').sub, first.sub);
  assert.equal(node.accounts.all().filter((a) => a.sub.startsWith('human:email:')).length, 2); // pat, anon
  // a refund (DELETE): the address still signs in to the account, which now holds nothing from the ticket
  assert.equal((await api('DELETE', '/tickets/' + encodeURIComponent('pat.buyer@gmail.com'))).status, 204);
  assert.equal(node.accounts.bySub(first.sub)!.ticket, undefined);
  const refunded = await emailLogin('pat.buyer@gmail.com', 'members');
  assert.equal(refunded.status, 403);
  assert.equal((await emailLogin('pat.buyer@gmail.com', 'account')).status, 200); // the account itself stays
  // a new purchase: the next sign-in takes it up again — same account, the ticket claimed by it
  assert.equal((await addTicket('pat.buyer@gmail.com', 'tickets:human:1c')).status, 201);
  const back = await emailLogin('pat.buyer@gmail.com', 'members');
  assert.equal(back.status, 200, JSON.stringify(back.body));
  assert.equal(tokenFrom(back.body.redirect, 'members').sub, first.sub);
  assert.equal(node.tickets.byEmail('pat.buyer@gmail.com')!.claimedBy, first.sub);
  assert.equal(node.accounts.bySub(first.sub)!.ticket!.source, 'api:tickets:human:1c');
  // a further purchase bringing more: merged onto the ticket AND the account
  assert.equal((await addTicket('pat.buyer@gmail.com', 'tickets:human:1d', { audiences: ['members', 'gate'], scopes: ['members:member', 'extra:use'] })).status, 200);
  assert.deepEqual(node.accounts.bySub(first.sub)!.ticket!.audiences, ['members', 'gate']);
  assert.ok(tokenFrom((await emailLogin('pat.buyer@gmail.com', 'gate')).body.redirect, 'gate').scopes.includes('extra:use'));
  // disabled: refused after the code, nothing minted
  node.accounts.update(first.sub, (a) => ({ ...a, disabled: true }));
  assert.equal((await emailLogin('pat.buyer@gmail.com', 'members')).status, 403);
  node.accounts.update(first.sub, (a) => ({ ...a, disabled: false }));
});

test('a ticket without an account yet, removed before the code comes back: refused; a ticket whose account dropped its email can’t make a second account', async () => {
  await addTicket('late@example.org', 'tickets:human:7');
  const state = await loginState('members');
  await post('/login/email/begin', { state, email: 'late@example.org' });
  node.tickets.remove('late@example.org');
  const r = await post('/login/email/finish', { state, email: 'late@example.org', code: lastCode('late@example.org') });
  assert.equal(r.status, 403);
  assert.match(r.body.error, /no ticket/);
  // claimed by an account that then unlinked the address (a local account that had linked it)
  node.tickets.add({ email: 'moved@example.org', source: 'admin:test', audiences: ['members'], scopes: ['members:member'] });
  await node.accounts.add({ sub: 'human:local:mover', username: 'mover', password: await hashPassword('mover password 1'), createdAt: '' });
  node.tickets.claim('moved@example.org', 'human:local:mover');
  const r2 = await emailLogin('moved@example.org', 'members');
  assert.equal(r2.status, 403);
  assert.match(r2.body.error, /no longer signs in by email/);
  assert.equal(node.accounts.byEmail('moved@example.org'), undefined);
});

test('rate limits: three codes per address and ten per client address in ten minutes, counted whether or not the address holds anything', async () => {
  const state = await loginState('members');
  for (let i = 0; i < 3; i++) assert.equal((await post('/login/email/begin', { state, email: 'limit.me@example.org' })).status, 200);
  const fourth = await post('/login/email/begin', { state, email: 'Limit.Me@example.org' });
  assert.equal(fourth.status, 429);
  assert.match(fourth.body.error, /wait 10 minutes/);
  const ip = { 'x-real-ip': '203.0.113.77' };
  for (let i = 0; i < 10; i++) assert.equal((await post('/login/email/begin', { state, email: `probe${i}@example.org` }, undefined, ip)).status, 200);
  assert.equal((await post('/login/email/begin', { state, email: 'probe-x@example.org' }, undefined, ip)).status, 429);
  // a ticket holder from that address is limited the same way
  assert.equal((await post('/login/email/begin', { state, email: 'pi@example.org' }, undefined, ip)).status, 429);
});

test('link an address under sign-in settings: the code proves the mailbox, and a ticket held for it is taken up by the existing account', async () => {
  outbox.length = 0;
  await addTicket('Dee.Holder@example.org', 'tickets:human:8');
  await node.accounts.add({ sub: 'human:local:dee', username: 'dee', password: await hashPassword('dee password 1'), createdAt: '' });
  const s = await post('/login/password', { state: await loginState('account'), username: 'dee', password: 'dee password 1' });
  const tok = rawToken(s.body.redirect);
  const me0 = JSON.parse((await get('/account/me', base, { authorization: `Bearer ${tok}` })).text);
  assert.equal(me0.canLinkEmail, true);
  assert.equal(me0.email, null);
  // the token is the credential; the mailbox is what's proved
  assert.equal((await post('/account/email/begin', { email: 'dee.holder@example.org' })).status, 401);
  const begin = await post('/account/email/begin', { email: 'dee.holder@example.org' }, tok);
  assert.equal(begin.status, 200);
  assert.equal(outbox.at(-1)!.to, 'dee.holder@example.org');
  // a login code can't finish a link, and the other way round
  assert.equal((await post('/login/email/finish', { state: await loginState('members'), email: 'dee.holder@example.org', code: lastCode('dee.holder@example.org') })).status, 401);
  assert.equal((await post('/account/email/finish', { email: 'dee.holder@example.org', code: '000000' }, tok)).status, 401);
  const fin = await post('/account/email/finish', { email: 'dee.holder@example.org', code: lastCode('dee.holder@example.org') }, tok);
  assert.equal(fin.status, 200, JSON.stringify(fin.body));
  assert.deepEqual(fin.body.email, { address: 'd***@example.org', since: fin.body.email.since, canUnlink: true });
  assert.deepEqual(fin.body.ticket.audiences, ['members']);
  assert.equal(fin.body.note, undefined);
  assert.equal(node.tickets.byEmail('dee.holder@example.org')!.claimedBy, 'human:local:dee');
  // no more than three link codes a day per account
  assert.equal((await post('/account/email/unlink', {}, tok)).status, 200);
  assert.equal((await post('/account/email/begin', { email: 'dee.two@example.org' }, tok)).status, 200);
  assert.equal((await post('/account/email/begin', { email: 'dee.three@example.org' }, tok)).status, 200);
  const capped = await post('/account/email/begin', { email: 'dee.four@example.org' }, tok);
  assert.equal(capped.status, 429);
  assert.match(capped.body.error, /link codes/);
  // (re-linking the address the ticket is on: the ticket is already this account's)
  node.accounts.update('human:local:dee', (a) => ({ ...a, email: { address: 'dee.holder@example.org', verifiedAt: '' } }));
  // from now on the address signs in to THAT account (no second row), with the ticket's grant
  const viaEmail = await emailLogin('dee.holder@example.org', 'members');
  assert.equal(viaEmail.status, 200, JSON.stringify(viaEmail.body));
  const p = tokenFrom(viaEmail.body.redirect, 'members');
  assert.equal(p.sub, 'human:local:dee');
  assert.deepEqual(p.scopes, ['members:member']);
  assert.equal(node.accounts.all().filter((a) => a.sub.startsWith('human:email:')).length, 2); // pat and anon only
  // an address that already signs in elsewhere can't be linked twice
  await node.accounts.add({ sub: 'human:local:eve', username: 'eve', password: await hashPassword('eve password 1'), createdAt: '' });
  const etok = rawToken((await post('/login/password', { state: await loginState('account'), username: 'eve', password: 'eve password 1' })).body.redirect);
  await post('/account/email/begin', { email: 'dee.holder@example.org' }, etok);
  const clash = await post('/account/email/finish', { email: 'dee.holder@example.org', code: lastCode('dee.holder@example.org') }, etok);
  assert.equal(clash.status, 409);
  // unlink: allowed with another way in; the ticket's grant stays on the row
  assert.equal((await post('/account/email/begin', { email: 'second@example.org' }, tok)).status, 400); // one address at a time
  const un = await post('/account/email/unlink', {}, tok);
  assert.equal(un.status, 200);
  assert.equal(un.body.email, null);
  assert.deepEqual(un.body.ticket.audiences, ['members']);
  assert.equal(node.accounts.bySub('human:local:dee')!.email, undefined);
  // …but not the last way in
  node.accounts.update('human:local:eve', (a) => { const { password: _p, ...rest } = a; return { ...rest, email: { address: 'eve@example.org', verifiedAt: '' } }; });
  const last = await post('/account/email/unlink', {}, etok);
  assert.equal(last.status, 400);
  assert.match(last.body.error, /only way/);
});

test('the sign-in page: the Email method, prefilled from ?email= for a ticket seller’s hand-off; the ticket hint only where tickets count', async () => {
  const page = await get('/login?audience=members');
  assert.match(page.text, /Email me a sign-in code/);
  assert.match(page.text, /Hold a ticket\?/);
  assert.match(page.text, /const prefill = "";/);
  const other = await get('/login?audience=eidoverse');
  assert.match(other.text, /Email me a sign-in code/); // a linked address signs in anywhere
  assert.doesNotMatch(other.text, /Hold a ticket\?/);
  assert.match(other.text, /Accounts are created by this home’s operator/);
  const pre = await get('/login?audience=members&email=' + encodeURIComponent('Buyer+1@example.org'));
  assert.match(pre.text, /const prefill = "Buyer\+1@example\.org";/);
  // not an address: nothing prefilled, nothing injected
  const junk = await get('/login?audience=members&email=' + encodeURIComponent('</script><script>alert(1)</script>'));
  assert.match(junk.text, /const prefill = "";/);
  assert.doesNotMatch(junk.text, /alert\(1\)/);
});

test('no EMAIL_PROVIDER: the method is hidden and its routes are off; no HN_TICKETS_TOKEN: the tickets API is 404', async () => {
  const n2 = makeNode({ ticketsToken: undefined }, { email: null });
  const b2 = `http://127.0.0.1:${await n2.start()}`;
  try {
    assert.equal(n2.email, null);
    const page = await get('/login?audience=members', b2);
    assert.doesNotMatch(page.text, /Email me a sign-in code/);
    assert.doesNotMatch(page.text, /Hold a ticket/);
    const pre = await get('/login?audience=members&email=a%40b.co', b2);
    assert.doesNotMatch(pre.text, /a@b\.co/);
    n2.tickets.add({ email: 'holder@example.org', source: 'admin:test', audiences: ['members'], scopes: ['members:member'] });
    const state = await loginState('members', b2);
    assert.equal((await post('/login/email/begin', { state, email: 'holder@example.org' }, undefined, {}, b2)).status, 404);
    assert.equal((await post('/login/email/finish', { state, email: 'holder@example.org', code: '123456' }, undefined, {}, b2)).status, 404);
    assert.equal((await addTicket('x@y.co', 'r9', {}, b2)).status, 404);
    assert.equal((await api('GET', '/tickets/x%40y.co', undefined, { b: b2 })).status, 404);
    assert.equal(n2.tickets.byEmail('x@y.co'), undefined);
  } finally {
    n2.stop();
  }
});

test('no config/ticket-defaults.json: no ticket can be made — 503, never a 201 with an empty grant', async () => {
  const n2 = makeNode({}, { defaults: null });
  const b2 = `http://127.0.0.1:${await n2.start()}`;
  try {
    assert.equal(n2.ticketDefaults.get().configured, false);
    for (const body of [{}, { audiences: ['members'], scopes: ['members:member'] }]) {
      const r = await addTicket('bare@example.org', 'r10', body, b2);
      assert.equal(r.status, 503, JSON.stringify(r.body));
    }
    assert.equal(n2.tickets.byEmail('bare@example.org'), undefined);
    assert.doesNotMatch((await get('/login?audience=members', b2)).text, /Hold a ticket\?/);
  } finally {
    n2.stop();
  }
});

// ── the ticket site mints invites for its holders' agents ──

async function enrol(code: string, name: string, b = base) {
  const key = generateKey();
  const r = await fetch(b + '/enroll', {
    method: 'POST', headers: hdrs({ 'content-type': 'application/json' }),
    body: JSON.stringify(makeEnrollRequest(key.privateKey, key.id, 'id.test', code, name)),
  });
  return { status: r.status, body: (await r.json()) as Record<string, any> };
}

test('invites: a ticket holder (signed in or not) sponsors agents under the invite policy; budget shared with the console; no_ticket', async () => {
  // never signed in: the ticket itself vouches, under a stable placeholder
  await addTicket('sponsor@example.org', 'tickets:human:sp', { name: 'Sam Sponsor' });
  assert.deepEqual((await api('POST', '/tickets/invites', { email: 'nobody@example.org', ref: 'x' })).body, { error: 'no_ticket' });
  assert.equal((await api('POST', '/tickets/invites', { email: 'nobody@example.org', ref: 'x' })).status, 404);
  assert.equal((await api('GET', '/tickets/invites?email=nobody%40example.org')).status, 404);
  const minted = await api('POST', '/tickets/invites', { email: 'sponsor@example.org', ref: 'tickets:human:sp', agentName: 'Ferro' });
  assert.equal(minted.status, 201, JSON.stringify(minted.body));
  assert.match(minted.body!.code, /^inv_/);
  assert.equal(minted.body!.enrolUrl, 'https://id.test/enroll');
  assert.equal(minted.body!.agentsMd, 'https://id.test/agents.md');
  assert.ok(Date.parse(minted.body!.expiresAt) - Date.now() > 13 * 86_400_000);
  const inv = node.invites.all().find((i) => i.code === minted.body!.code)!;
  assert.equal(inv.sponsor, 'ticket:tickets:human:sp');
  assert.deepEqual([...inv.scopes].sort(), ['docs:use', 'members:member']); // delegable ∩ ticket, plus baseline
  assert.deepEqual(inv.audiences, ['members']); // by the policy's rules, never the ticket's own list
  assert.deepEqual(inv.claims, { tier: 'sponsored', sponsor: 'ticket:tickets:human:sp', sponsorName: 'Sam Sponsor' });
  assert.equal(inv.maxUses, 1);
  // by ref alone works too; the list shows the code while unclaimed
  assert.equal((await api('POST', '/tickets/invites', { ref: 'tickets:human:sp' })).status, 201);
  const list = await api('GET', '/tickets/invites?email=' + encodeURIComponent('Sponsor@example.org'));
  assert.equal(list.status, 200);
  assert.equal(list.body!.invites.length, 2);
  assert.deepEqual(Object.keys(list.body!.invites[0]).sort(), ['agentName', 'code', 'createdAt', 'expiresAt']);
  assert.equal(list.body!.invites[0].agentName, 'Ferro');
  // an agent enrols with it: it gets the ticket's audiences, carries the sponsor, and the code is spent
  const agent = await enrol(minted.body!.code, 'Ferro');
  assert.equal(agent.status, 200, JSON.stringify(agent.body));
  const principal = node.principals.bySub(agent.body.sub)!;
  assert.deepEqual(principal.audiences, ['members']);
  assert.deepEqual(principal.claims?.sponsor, 'ticket:tickets:human:sp');
  const after = (await api('GET', '/tickets/invites?email=sponsor%40example.org')).body!.invites.find((i: { agentName: string }) => i.agentName === 'Ferro');
  assert.equal(after.code, undefined);
  assert.equal(after.claimedBy, agent.body.sub);
  // the budget: three unclaimed at a time
  assert.equal((await api('POST', '/tickets/invites', { email: 'sponsor@example.org', ref: 'tickets:human:sp' })).status, 201);
  assert.equal((await api('POST', '/tickets/invites', { email: 'sponsor@example.org', ref: 'tickets:human:sp' })).status, 201);
  const full = await api('POST', '/tickets/invites', { email: 'sponsor@example.org', ref: 'tickets:human:sp' });
  assert.deepEqual(full, { status: 409, body: { error: 'budget' } });

  // signed in: the account is the sponsor, and the console and the API draw on one pool
  await node.accounts.add({ sub: 'human:local:cal', username: 'cal', password: await hashPassword('cal password 1'), scopes: ['members:member'], createdAt: '' });
  await addTicket('cal@example.org', 'tickets:human:cal');
  node.accounts.update('human:local:cal', (a) => ({ ...a, email: { address: 'cal@example.org', verifiedAt: '' }, ticket: { email: 'cal@example.org', source: 'api:tickets:human:cal', claimedAt: '', audiences: ['members'], scopes: ['members:member'] } }));
  node.tickets.claim('cal@example.org', 'human:local:cal');
  const ctok = rawToken((await post('/login/password', { state: await loginState('console'), username: 'cal', password: 'cal password 1' })).body.redirect);
  assert.equal((await post('/console/invites', { label: 'one' }, ctok)).status, 200);
  assert.equal((await post('/console/invites', { label: 'two' }, ctok)).status, 200);
  const viaApi = await api('POST', '/tickets/invites', { email: 'cal@example.org', ref: 'tickets:human:cal', agentName: 'three' });
  assert.equal(viaApi.status, 201, JSON.stringify(viaApi.body));
  assert.equal(node.invites.all().find((i) => i.code === viaApi.body!.code)!.sponsor, 'human:local:cal');
  assert.equal((await api('POST', '/tickets/invites', { email: 'cal@example.org', ref: 'tickets:human:cal' })).status, 409);
  assert.equal((await post('/console/invites', { label: 'four' }, ctok)).status, 429);
  assert.equal((await api('GET', '/tickets/invites?email=cal%40example.org')).body!.invites.length, 3);
  // a disabled account sponsors nothing
  node.accounts.update('human:local:cal', (a) => ({ ...a, disabled: true }));
  assert.equal((await api('POST', '/tickets/invites', { email: 'cal@example.org', ref: 'tickets:human:cal' })).status, 403);
  node.accounts.update('human:local:cal', (a) => ({ ...a, disabled: false }));
});

test('/agents.md: the deployment’s own wording when config has one, else the built-in guide', async () => {
  const builtIn = await get('/agents.md');
  assert.equal(builtIn.status, 200);
  assert.match(builtIn.text, /enroll/i);
  writeFileSync(join(node.cfg.configDir, 'agents.md'), '# our agents\n\nNo ticket-holding human? Ask on Discord.\n');
  const own = await get('/agents.md');
  assert.equal(own.status, 200);
  assert.match(own.text, /Ask on Discord/);
});
