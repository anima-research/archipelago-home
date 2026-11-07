/**
 * Ticket holders sign in by email: a real HomeNode on a random port, the
 * mail caught at the EmailSender seam, Stripe's webhook signed for real.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HomeNode, type ServerConfig } from '../src/server.js';
import { verifyToken, type Aid1Payload } from '../src/token.js';
import { hashPassword } from '../src/accounts.js';
import { signStripePayload } from '../src/stripe.js';
import { EMAIL_SENT_MESSAGE } from '../src/human.js';
import type { EmailSender } from '../src/email.js';

const SECRET = 'whsec_test';
let node: HomeNode;
let base: string;
let ipSeq = 0;
/** Every message the node sent, newest last. */
const outbox: Array<{ to: string; subject: string; text: string }> = [];
const sender: EmailSender = { async send(to, subject, text) { outbox.push({ to, subject, text }); } };
const lastCode = (to: string) => /\b(\d{6})\b/.exec([...outbox].reverse().find((m) => m.to === to)!.text)![1]!;

function makeNode(extra: Partial<ServerConfig> = {}, opts: { email?: EmailSender | null; defaults?: unknown } = {}): HomeNode {
  const dir = mkdtempSync(join(tmpdir(), 'hn-email-'));
  writeFileSync(join(dir, 'roles.json'), JSON.stringify({ guildId: 'g1', map: {} }));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({ principals: [] }));
  writeFileSync(join(dir, 'audiences.json'), JSON.stringify({
    members: { redirect: 'https://members.test/auth', requiredScopes: ['members:member'] },
    eidoverse: { redirect: 'https://worlds.test/auth', requiredScopes: ['worlds:join'] },
    gate: { redirect: 'https://gate.test/auth' }, // no requiredScopes: takes any grant — a ticket must not open it
  }));
  if (opts.defaults !== null) writeFileSync(join(dir, 'ticket-defaults.json'), JSON.stringify(opts.defaults ?? { audiences: ['members'], scopes: ['members:member'] }));
  return new HomeNode(
    { iss: 'id.test', publicUrl: 'https://id.test', bind: '127.0.0.1', port: 0, dataDir: dir, configDir: dir, stripeWebhookSecret: SECRET, ...extra },
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
async function webhook(event: unknown, opts: { secret?: string; t?: number; header?: string; b?: string } = {}) {
  const body = JSON.stringify(event);
  const r = await fetch((opts.b ?? base) + '/stripe/webhook', {
    method: 'POST', body,
    headers: hdrs({ 'content-type': 'application/json', 'stripe-signature': opts.header ?? signStripePayload(body, opts.secret ?? SECRET, opts.t) }),
  });
  return { status: r.status, body: (await r.json()) as Record<string, any> };
}
const checkout = (id: string, email: string | null, type = 'checkout.session.completed') => ({
  id, type, data: { object: { object: 'checkout.session', ...(email ? { customer_details: { email } } : {}) } },
});
async function emailLogin(email: string, audience: string, code?: string) {
  const state = await loginState(audience);
  const begin = await post('/login/email/begin', { state, email });
  assert.equal(begin.status, 200, JSON.stringify(begin.body));
  return post('/login/email/finish', { state, email, code: code ?? lastCode(email) });
}

test('stripe webhook: a signed checkout adds a ticket with the configured defaults; redeliveries, bad signatures and other events add nothing', async () => {
  const ok = await webhook(checkout('evt_1', 'Pat.Buyer+x@gmail.com'));
  assert.deepEqual(ok, { status: 200, body: { received: true, ticket: 'added' } });
  const t = node.tickets.byEmail('patbuyer@gmail.com')!;
  assert.equal(t.email, 'Pat.Buyer+x@gmail.com');
  assert.equal(t.source, 'stripe:evt_1');
  assert.deepEqual(t.audiences, ['members']);
  assert.deepEqual(t.scopes, ['members:member']);
  // the same event again (Stripe retries): seen, nothing added
  assert.deepEqual((await webhook(checkout('evt_1', 'pat.buyer@gmail.com'))).body, { received: true, duplicate: 'evt_1' });
  // a second purchase with the same mailbox: still the one ticket
  assert.deepEqual((await webhook(checkout('evt_2', 'patbuyer@googlemail.com'))).body, { received: true, ticket: 'existing' });
  assert.equal(node.tickets.all().length, 1);
  // refused: wrong secret, stale timestamp, no header, garbage body
  assert.equal((await webhook(checkout('evt_3', 'x@y.co'), { secret: 'whsec_wrong' })).status, 400);
  assert.equal((await webhook(checkout('evt_3', 'x@y.co'), { t: Math.floor(Date.now() / 1000) - 600 })).status, 400);
  assert.equal((await webhook(checkout('evt_3', 'x@y.co'), { header: '' })).status, 400);
  assert.equal(node.tickets.byEmail('x@y.co'), undefined);
  const garbage = await fetch(base + '/stripe/webhook', { method: 'POST', body: 'nope', headers: hdrs({ 'stripe-signature': signStripePayload('nope', SECRET) }) });
  assert.equal(garbage.status, 400);
  // other events, and a payment without an address: 200, ignored
  assert.deepEqual((await webhook({ id: 'evt_4', type: 'customer.created', data: { object: { email: 'c@d.co' } } })).body, { received: true, ignored: 'customer.created' });
  assert.deepEqual((await webhook(checkout('evt_5', null, 'payment_intent.succeeded'))).body, { received: true, ignored: 'payment_intent.succeeded' });
  assert.equal(node.tickets.all().length, 1);
  // a payment intent that does carry an address
  assert.deepEqual((await webhook({ id: 'evt_6', type: 'payment_intent.succeeded', data: { object: { receipt_email: 'pi@example.org' } } })).body, { received: true, ticket: 'added' });
  assert.equal(node.tickets.byEmail('pi@example.org')!.source, 'stripe:evt_6');
});

test('begin: the same answer whether or not the address holds a ticket; a code goes out only to a holder', async () => {
  outbox.length = 0;
  const state = await loginState('members');
  const unknown = await post('/login/email/begin', { state, email: 'stranger@example.org' });
  assert.deepEqual(unknown, { status: 200, body: { ok: true, message: EMAIL_SENT_MESSAGE } });
  assert.equal(outbox.length, 0);
  // nothing pending for it either: a guess has nothing to match
  const guess = await post('/login/email/finish', { state, email: 'stranger@example.org', code: '000000' });
  assert.equal(guess.status, 400);
  assert.match(guess.body.error, /no code is pending/);

  const holder = await post('/login/email/begin', { state, email: 'pat.buyer@gmail.com' });
  assert.deepEqual(holder, unknown); // byte for byte the same
  assert.equal(outbox.length, 1);
  assert.equal(outbox[0]!.to, 'pat.buyer@gmail.com');
  assert.match(outbox[0]!.text, /^Your sign-in code is \d{6}\. It expires in 10 minutes\. If you didn't request this, ignore it\.$/);
  assert.match(outbox[0]!.subject, /\d{6}/);
  // malformed input, dead state
  assert.equal((await post('/login/email/begin', { state, email: 'not-an-address' })).status, 400);
  assert.equal((await post('/login/email/begin', { state: 'nope', email: 'pat.buyer@gmail.com' })).status, 400);
});

test('finish: five wrong codes spend it; the right code makes a human:email: account, claims the ticket and signs in — for the ticket’s audiences only', async () => {
  const state = await loginState('members');
  await post('/login/email/begin', { state, email: 'pat.buyer@gmail.com' });
  const code = lastCode('pat.buyer@gmail.com');
  for (let i = 0; i < 4; i++) {
    const r = await post('/login/email/finish', { state, email: 'pat.buyer@gmail.com', code: '000000' });
    assert.equal(r.status, 401);
    assert.equal(r.body.restart, undefined);
  }
  const fifth = await post('/login/email/finish', { state, email: 'pat.buyer@gmail.com', code: '000000' });
  assert.equal(fifth.status, 401);
  assert.equal(fifth.body.restart, true);
  const spent = await post('/login/email/finish', { state, email: 'pat.buyer@gmail.com', code });
  assert.equal(spent.status, 400); // the right code no longer counts
  assert.equal(node.accounts.byEmail('pat.buyer@gmail.com'), undefined);

  // a fresh code: in (the address as typed at begin is the one on the row)
  const done = await emailLogin('Pat.Buyer@gmail.com', 'members');
  assert.equal(done.status, 200, JSON.stringify(done.body));
  const p = tokenFrom(done.body.redirect, 'members');
  assert.match(p.sub, /^human:email:[A-Za-z0-9_-]{12}$/);
  assert.equal(p.kind, 'human');
  assert.equal(p.name, 'Pat.Buyer');
  assert.deepEqual(p.scopes, ['members:member']);
  assert.ok(p.jti && p.exp - p.iat === 600);
  const row = node.accounts.bySub(p.sub)!;
  assert.equal(row.email!.address, 'Pat.Buyer@gmail.com');
  assert.ok(row.email!.verifiedAt);
  assert.deepEqual(row.ticket!.audiences, ['members']);
  assert.equal(row.ticket!.source, 'stripe:evt_1');
  assert.equal(row.scopes, undefined); // the grant lives on the ticket snapshot, audience-bound
  assert.equal(node.tickets.byEmail('patbuyer@gmail.com')!.claimedBy, p.sub);
  // the code is single-use
  assert.equal((await post('/login/email/finish', { state, email: 'Pat.Buyer@gmail.com', code: lastCode('Pat.Buyer@gmail.com') })).status, 400);
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
});

test('a second sign-up with the same mailbox is the same account; spelling, case and +tag don’t matter; a removed ticket doesn’t sign the account out', async () => {
  const first = node.accounts.byEmail('pat.buyer@gmail.com')!;
  const again = await emailLogin('PAT.BUYER+other@gmail.com', 'members');
  assert.equal(again.status, 200, JSON.stringify(again.body));
  assert.equal(tokenFrom(again.body.redirect, 'members').sub, first.sub);
  assert.equal(node.accounts.all().filter((a) => a.email).length, 1);
  // hn ticket rm: no new sign-ups with it, but the account it made keeps what it was given
  node.tickets.remove('pat.buyer@gmail.com');
  const still = await emailLogin('pat.buyer@gmail.com', 'members');
  assert.equal(still.status, 200);
  assert.deepEqual(tokenFrom(still.body.redirect, 'members').scopes, ['members:member']);
  // disabled: refused after the code, nothing minted
  node.accounts.update(first.sub, (a) => ({ ...a, disabled: true }));
  assert.equal((await emailLogin('pat.buyer@gmail.com', 'members')).status, 403);
  node.accounts.update(first.sub, (a) => ({ ...a, disabled: false }));
});

test('a ticket without an account yet, removed before the code comes back: refused; a ticket whose account dropped its email can’t make a second account', async () => {
  await webhook(checkout('evt_7', 'late@example.org'));
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
  await webhook(checkout('evt_8', 'Dee.Holder@example.org'));
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
  assert.equal((await post('/login/email/finish', { state: await loginState('members'), email: 'dee.holder@example.org', code: lastCode('dee.holder@example.org') })).status, 400);
  assert.equal((await post('/account/email/finish', { email: 'dee.holder@example.org', code: '000000' }, tok)).status, 401);
  const fin = await post('/account/email/finish', { email: 'dee.holder@example.org', code: lastCode('dee.holder@example.org') }, tok);
  assert.equal(fin.status, 200, JSON.stringify(fin.body));
  assert.deepEqual(fin.body.email, { address: 'd***@example.org', since: fin.body.email.since, canUnlink: true });
  assert.deepEqual(fin.body.ticket.audiences, ['members']);
  assert.equal(fin.body.note, undefined);
  assert.equal(node.tickets.byEmail('dee.holder@example.org')!.claimedBy, 'human:local:dee');
  // from now on the address signs in to THAT account (no second row), with the ticket's grant
  const viaEmail = await emailLogin('dee.holder@example.org', 'members');
  assert.equal(viaEmail.status, 200, JSON.stringify(viaEmail.body));
  const p = tokenFrom(viaEmail.body.redirect, 'members');
  assert.equal(p.sub, 'human:local:dee');
  assert.deepEqual(p.scopes, ['members:member']);
  assert.equal(node.accounts.all().filter((a) => a.sub.startsWith('human:email:')).length, 1); // pat's only
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

test('the sign-in page: the Email method, prefilled from ?email= for a ticket seller’s hand-off', async () => {
  const page = await get('/login?audience=members');
  assert.match(page.text, /Email me a sign-in code/);
  assert.match(page.text, /const prefill = "";/);
  const pre = await get('/login?audience=members&email=' + encodeURIComponent('Buyer+1@example.org'));
  assert.match(pre.text, /const prefill = "Buyer\+1@example\.org";/);
  // not an address: nothing prefilled, nothing injected
  const junk = await get('/login?audience=members&email=' + encodeURIComponent('</script><script>alert(1)</script>'));
  assert.match(junk.text, /const prefill = "";/);
  assert.doesNotMatch(junk.text, /alert\(1\)/);
});

test('no EMAIL_PROVIDER: the method is hidden and its routes are off; no STRIPE_WEBHOOK_SECRET: the webhook is 404', async () => {
  const n2 = makeNode({ stripeWebhookSecret: undefined }, { email: null });
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
    assert.equal((await webhook(checkout('evt_9', 'x@y.co'), { b: b2 })).status, 404);
    assert.equal(n2.tickets.byEmail('x@y.co'), undefined);
  } finally {
    n2.stop();
  }
});

test('no config/ticket-defaults.json: a Stripe ticket grants nothing (it still signs the holder in, to nothing)', async () => {
  const n2 = makeNode({}, { defaults: null });
  const b2 = `http://127.0.0.1:${await n2.start()}`;
  try {
    assert.equal(n2.ticketDefaults.get().configured, false);
    assert.deepEqual((await webhook(checkout('evt_10', 'bare@example.org'), { b: b2 })).body, { received: true, ticket: 'added' });
    assert.deepEqual(n2.tickets.byEmail('bare@example.org')!.audiences, []);
    const state = await loginState('members', b2);
    await post('/login/email/begin', { state, email: 'bare@example.org' }, undefined, {}, b2);
    const r = await post('/login/email/finish', { state, email: 'bare@example.org', code: lastCode('bare@example.org') }, undefined, {}, b2);
    assert.equal(r.status, 403);
    assert.ok(n2.accounts.byEmail('bare@example.org')); // signed in, holding nothing
  } finally {
    n2.stop();
  }
});
