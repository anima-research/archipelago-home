/**
 * The second review's probes, kept: guessing is charged to the guesser,
 * holder and stranger stay indistinguishable, invites carry only the
 * ticket's reach and die with its refund, refunds are ordered and
 * retryable, and the small things (auth spelling, control characters,
 * names, bursts, GET /enroll).
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HomeNode, type ServerConfig } from '../src/server.js';
import { verifyToken } from '../src/token.js';
import { hashPassword } from '../src/accounts.js';
import { generateKey } from '../src/keys.js';
import { makeEnrollRequest, makeTokenRequest } from '../src/statements.js';
import { emailKey } from '../src/google.js';
import type { EmailSender } from '../src/email.js';

const TOKEN = 'review-tickets-token-0123456789abcdef';
const DEFAULTS = {
  audiences: ['members'], scopes: ['members:member'],
  allowed: { audiences: ['members', 'gate', 'ghost'], scopes: ['members:member', 'extra:use'] },
  invites: { active: 3, lifetime: 5 },
};
// a policy whose `always` rules would open the whole home, and a console gate the holders lack
const POLICY = {
  console: { requiredScopes: ['worlds:join'] },
  scopes: { 'members:member': ['delegable'], 'extra:use': ['delegable'], 'docs:use': ['baseline', 'delegable'], 'worlds:join': ['delegable', 'resident'] },
  audiences: [{ audience: 'members', when: ['members:*'] }, { audience: 'docs', always: true }, { audience: 'eidoverse', always: true }],
};
const outbox: Array<{ to: string; text: string }> = [];
const sender: EmailSender = { async send(to, _subject, text) { outbox.push({ to, text }); } };
let node: HomeNode;
let base: string;
let ipSeq = 0;

function makeNode(extra: Partial<ServerConfig> = {}, defaults: unknown = DEFAULTS): HomeNode {
  const dir = mkdtempSync(join(tmpdir(), 'hn-review-'));
  writeFileSync(join(dir, 'roles.json'), JSON.stringify({ guildId: 'g1', map: {} }));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({ principals: [] }));
  writeFileSync(join(dir, 'audiences.json'), JSON.stringify({
    members: { redirect: 'https://members.test/auth', requiredScopes: ['members:member'] },
    eidoverse: { redirect: 'https://worlds.test/auth', requiredScopes: ['worlds:join'] },
    docs: { redirect: 'https://docs.test/auth' },
    gate: { redirect: 'https://gate.test/auth' },
  }));
  if (defaults !== null) writeFileSync(join(dir, 'ticket-defaults.json'), JSON.stringify(defaults));
  writeFileSync(join(dir, 'invite-policy.json'), JSON.stringify(POLICY));
  return new HomeNode({ iss: 'id.test', publicUrl: 'https://id.test', bind: '127.0.0.1', port: 0, dataDir: dir, configDir: dir, ticketsToken: TOKEN, ...extra }, { email: sender });
}
before(async () => {
  node = makeNode();
  base = `http://127.0.0.1:${await node.start()}`;
});
after(() => node.stop());

const freshIp = () => `10.2.${(ipSeq >> 8) & 255}.${ipSeq++ & 255}`;
async function raw(method: string, path: string, body?: unknown, extra: Record<string, string> = {}, b = base) {
  const r = await fetch(b + path, {
    method, ...(body !== undefined ? { body: typeof body === 'string' ? body : JSON.stringify(body) } : {}),
    headers: { 'x-real-ip': freshIp(), 'content-type': 'application/json', ...extra }, redirect: 'manual',
  });
  const text = await r.text();
  let parsed: any = text;
  try { parsed = text ? JSON.parse(text) : null; } catch { /* html */ }
  return { status: r.status, body: parsed as any };
}
const post = (path: string, body: unknown, extra: Record<string, string> = {}) => raw('POST', path, body, extra);
const api = (method: string, path: string, body?: unknown, extra: Record<string, string> = {}, b = base) => raw(method, path, body, { authorization: `Bearer ${TOKEN}`, ...extra }, b);
async function state(aud = 'members') {
  return /"state":"([^"]+)"/.exec((await raw('GET', `/login?audience=${aud}`)).body)![1]!;
}
const settle = () => new Promise((r) => setImmediate(r));
const lastCode = (to: string) => /code is ([a-z0-9]+)\./.exec([...outbox].reverse().find((m) => emailKey(m.to) === emailKey(to))!.text)![1]!;
async function emailLogin(email: string, aud: string, extra: Record<string, string> = {}) {
  const st = await state(aud);
  const b = await post('/login/email/begin', { state: st, email }, extra);
  if (b.status !== 200) return b;
  await settle();
  return post('/login/email/finish', { state: st, email, code: lastCode(email) }, extra);
}
const tokOf = (redirect: string) => /#token=(.+)$/.exec(redirect ?? '')?.[1];
const scopesFor = (r: { status: number; body: any }, aud: string) => {
  const t = tokOf(r.body?.redirect);
  if (!t) return `${r.status}`;
  const v = verifyToken(t, { issuerId: node.issuer.id, iss: 'id.test', aud });
  return v.ok ? v.payload.scopes.join(' ') : v.reason;
};
async function enrol(code: string, name: string) {
  const key = generateKey();
  const r = await raw('POST', '/enroll', makeEnrollRequest(key.privateKey, key.id, 'id.test', code, name));
  return { ...r, key };
}
const strip = (r: { status: number; body: unknown }) => JSON.stringify({ s: r.status, b: r.body });

test('oracle: a holder and a stranger get byte-identical answers through begins, wrong guesses and never-begun finishes', async () => {
  await api('POST', '/tickets', { email: 'holder@example.org', ref: 'h1' });
  const seqs: string[][] = [];
  for (const email of ['holder@example.org', 'stranger@example.org']) {
    const out: string[] = [];
    const st = await state();
    out.push(strip(await post('/login/email/finish', { state: st, email, code: '123456' }))); // before any begin
    out.push(strip(await post('/login/email/begin', { state: st, email })));
    for (let i = 0; i < 6; i++) out.push(strip(await post('/login/email/finish', { state: st, email, code: String(100000 + i) })));
    out.push(strip(await post('/login/email/begin', { state: st, email })));
    out.push(strip(await post('/login/email/finish', { state: st, email, code: 'abcdef' })));
    out.push(strip(await post('/login/email/begin', { state: st, email })));
    out.push(strip(await post('/login/email/begin', { state: st, email }))); // the fourth in ten minutes
    seqs.push(out);
  }
  assert.deepEqual(seqs[0], seqs[1]);
  assert.equal(seqs[0]![0], '{"s":401,"b":{"error":"wrong or expired code"}}');
  assert.equal(seqs[0]!.at(-1), '{"s":429,"b":{"error":"too many codes requested — wait 10 minutes"}}');
  await settle();
  assert.deepEqual(outbox.filter((m) => m.to === 'holder@example.org').length, 3);
  assert.deepEqual(outbox.filter((m) => m.to === 'stranger@example.org').length, 0);
  // the holder's code survived all of it
  const st = await state();
  const ok = await post('/login/email/finish', { state: st, email: 'holder@example.org', code: lastCode('holder@example.org') });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
});

test('guessing is charged to the guesser: 20 wrong an hour per client address, 10 a day per (address, client) pair; nothing locks the holder', async () => {
  for (let v = 0; v < 3; v++) await api('POST', '/tickets', { email: `att${v}@example.org`, ref: `A${v}` });
  // one source, one state, no begin: 30 guesses at 3 victims — the source runs dry at 20
  const ip = { 'x-real-ip': '198.51.100.7' };
  const st = /"state":"([^"]+)"/.exec((await raw('GET', '/login?audience=members', undefined, ip)).body)![1]!;
  const codes: number[] = [];
  for (let v = 0; v < 3; v++) for (let i = 0; i < 10; i++) codes.push((await post('/login/email/finish', { state: st, email: `att${v}@example.org`, code: String(100000 + i) }, ip)).status);
  assert.deepEqual([codes.slice(0, 20).every((s) => s === 401), codes.slice(20).every((s) => s === 429)], [true, true]);
  // the victims are untouched: each signs in from home
  for (let v = 0; v < 3; v++) assert.equal((await emailLogin(`att${v}@example.org`, 'members')).status, 200, `att${v}`);
  // a pending code: 10 guesses from one source lock that source for that address only; the holder's code still works
  await api('POST', '/tickets', { email: 'victim@example.org', ref: 'V1' });
  const vst = await state();
  await post('/login/email/begin', { state: vst, email: 'victim@example.org' });
  await settle();
  const guesser = { 'x-real-ip': '198.51.100.8' };
  for (let i = 0; i < 10; i++) assert.equal((await post('/login/email/finish', { state: await state(), email: 'victim@example.org', code: String(200000 + i) }, guesser)).status, 401);
  assert.equal((await post('/login/email/finish', { state: await state(), email: 'victim@example.org', code: '200010' }, guesser)).status, 429);
  assert.equal((await post('/login/email/begin', { state: await state(), email: 'victim@example.org' }, guesser)).status, 429);
  assert.equal((await post('/login/email/begin', { state: await state(), email: 'att0@example.org' }, guesser)).status, 200); // another address: fine
  const vf = await post('/login/email/finish', { state: vst, email: 'victim@example.org', code: lastCode('victim@example.org') });
  assert.equal(vf.status, 200, JSON.stringify(vf.body));
  // ten more guesses from ten more sources don't lock anyone either: at 30 the address is hardened, not refused
  await api('POST', '/tickets', { email: 'hard@example.org', ref: 'HD1' });
  await post('/login/email/begin', { state: await state(), email: 'hard@example.org' });
  await settle();
  const six = lastCode('hard@example.org');
  assert.match(six, /^\d{6}$/);
  for (let i = 0; i < 30; i++) assert.equal((await post('/login/email/finish', { state: await state(), email: 'hard@example.org', code: String(300000 + i) })).status, 401, String(i));
  // the six-digit code pending from before no longer counts; the next request sends a long one, which does
  assert.equal((await post('/login/email/finish', { state: await state(), email: 'hard@example.org', code: six })).status, 401);
  const hst = await state();
  assert.equal((await post('/login/email/begin', { state: hst, email: 'hard@example.org' })).status, 200);
  await settle();
  const long = lastCode('hard@example.org');
  assert.match(long, /^[a-z2-7]{10}$/);
  assert.equal((await post('/login/email/finish', { state: await state(), email: 'hard@example.org', code: '000000' })).status, 401);
  const hf = await post('/login/email/finish', { state: hst, email: 'hard@example.org', code: long.toUpperCase().replace(/(.{5})/, '$1-') });
  assert.equal(hf.status, 200, JSON.stringify(hf.body));
  // a stranger's decoy hardens the same way (indistinguishable)
  for (let i = 0; i < 30; i++) await post('/login/email/finish', { state: await state(), email: 'nobody-hard@example.org', code: String(300000 + i) });
  assert.equal((await post('/login/email/begin', { state: await state(), email: 'nobody-hard@example.org' })).status, 200);
  assert.equal((await post('/login/email/finish', { state: await state(), email: 'nobody-hard@example.org', code: 'abcdefghij' })).status, 401);
});

test('mail per address is capped at 20 a day, counted for strangers too', async () => {
  await api('POST', '/tickets', { email: 'daily@example.org', ref: 'D1' });
  const results: number[] = [];
  for (let i = 0; i < 21; i++) {
    // each sign-in succeeds, which clears the ten-minute limit; the daily one keeps counting
    const r = await emailLogin('daily@example.org', 'members');
    results.push(r.status);
  }
  assert.deepEqual([results.slice(0, 20).every((s) => s === 200), results[20]], [true, 429]);
  assert.match((await post('/login/email/begin', { state: await state(), email: 'daily@example.org' })).body.error, /today/);
  for (let i = 0; i < 20; i++) await post('/login/email/begin', { state: await state(), email: `s-daily@example.org` }).catch(() => {});
  // (three of those were 429 by the ten-minute limit; the daily counter still counted the rest)
});

test('a code is spent only once the account write went through: a held lock answers 409 and the code still works', async () => {
  await api('POST', '/tickets', { email: 'lk@example.org', ref: 'LK1' });
  const st = await state();
  await post('/login/email/begin', { state: st, email: 'lk@example.org' });
  await settle();
  const code = lastCode('lk@example.org');
  const lock = join(node.cfg.dataDir, 'accounts.json.lock');
  writeFileSync(lock, String(process.pid));
  const held = await post('/login/email/finish', { state: st, email: 'lk@example.org', code });
  rmSync(lock, { force: true });
  assert.equal(held.status, 409, JSON.stringify(held.body));
  const ok = await post('/login/email/finish', { state: st, email: 'lk@example.org', code });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
});

test('refund: the account copy, unclaimed invites and enrolled agents are taken back FIRST; a failure leaves the ticket to retry; a stray copy is repaired', async () => {
  await api('POST', '/tickets', { email: 'r@example.org', ref: 'R1', name: 'Ree' });
  assert.equal(scopesFor(await emailLogin('r@example.org', 'members'), 'members'), 'members:member');
  const sub = node.accounts.byEmail('r@example.org')!.sub;
  const tid = node.tickets.byEmail('r@example.org')!.id;
  // an agent enrolled through the ticket, and an invite still unclaimed
  const inv1 = await api('POST', '/tickets/invites', { email: 'r@example.org', ref: 'R1', agentName: 'keeper' });
  const inv2 = await api('POST', '/tickets/invites', { email: 'r@example.org', ref: 'R1', agentName: 'unused' });
  const agent = await enrol(inv1.body.code, 'keeper');
  assert.equal(agent.status, 200, JSON.stringify(agent.body));
  assert.deepEqual(node.principals.bySub(agent.body.sub)!.audiences, ['members']);
  assert.equal(node.principals.bySub(agent.body.sub)!.sponsorTicket, tid);
  // the accounts file is locked: the refund fails whole, the ticket stays
  const lock = join(node.cfg.dataDir, 'accounts.json.lock');
  writeFileSync(lock, String(process.pid));
  const d1 = await api('DELETE', '/tickets/' + encodeURIComponent('R@Example.org'));
  rmSync(lock, { force: true });
  assert.equal(d1.status, 500);
  assert.ok(node.tickets.byEmail('r@example.org'));
  assert.ok(node.accounts.bySub(sub)!.ticket);
  // retried: everything goes, the identities stay
  const d2 = await api('DELETE', '/tickets/' + encodeURIComponent('R@Example.org'));
  assert.equal(d2.status, 204);
  assert.equal(node.tickets.byEmail('r@example.org'), undefined);
  assert.equal(node.accounts.bySub(sub)!.ticket, undefined);
  assert.equal(node.invites.all().find((i) => i.code === inv2.body.code), undefined); // revoked
  const p = node.principals.bySub(agent.body.sub)!;
  assert.deepEqual([p.scopes, p.audiences], [[], []]); // stripped, not deleted
  assert.match(p.notes!, /refunded/);
  assert.equal((await raw('POST', '/token', makeTokenRequest(agent.key.privateKey, agent.key.id, 'id.test', 'members'))).status, 403);
  assert.equal((await enrol(inv2.body.code, 'late')).status, 403);
  assert.equal((await emailLogin('r@example.org', 'members')).status, 403);
  assert.equal((await emailLogin('r@example.org', 'account')).status, 200); // the account itself stays
  // the refunded ticket still lists, says so, and its refs are spent for any mailbox
  const gone = await api('GET', '/tickets/invites?email=r%40example.org');
  assert.equal(gone.status, 200);
  assert.equal(gone.body.refunded, true);
  assert.equal(gone.body.invites.length, 1); // the claimed one; the unclaimed one was revoked
  assert.equal((await api('GET', '/tickets/invites?ref=R1')).body.refunded, true);
  assert.equal((await api('POST', '/tickets', { email: 'r@example.org', ref: 'R1' })).status, 410);
  assert.equal((await api('POST', '/tickets', { email: 'other@example.org', ref: 'R1' })).status, 410);
  // a new purchase: a new ticket, taken up at the next sign-in
  assert.equal((await api('POST', '/tickets', { email: 'r@example.org', ref: 'R3' })).status, 201);
  assert.equal(scopesFor(await emailLogin('r@example.org', 'members'), 'members'), 'members:member');
  assert.equal(node.tickets.byEmail('r@example.org')!.claimedBy, sub);
  // a stray copy with no ticket behind it: DELETE repairs it rather than 404
  node.tickets.remove('r@example.org');
  assert.ok(node.accounts.bySub(sub)!.ticket);
  assert.equal((await api('DELETE', '/tickets/r%40example.org')).status, 204);
  assert.equal(node.accounts.bySub(sub)!.ticket, undefined);
  assert.equal((await api('DELETE', '/tickets/r%40example.org')).status, 404);
});

test('invites: the ticket’s reach only (always-rules don’t widen it), one budget across placeholder and account, lifetime cap, unique placeholders, email/ref must agree', async () => {
  await api('POST', '/tickets', { email: 'b@example.org', ref: 'B1', name: 'Bea' });
  const tid = node.tickets.byEmail('b@example.org')!.id;
  const pre: number[] = [];
  for (let i = 0; i < 4; i++) pre.push((await api('POST', '/tickets/invites', { email: 'b@example.org', agentName: `pre${i}` })).status);
  assert.deepEqual(pre, [201, 201, 201, 409]);
  const inv = node.invites.all().filter((i) => i.ticket === tid);
  assert.equal(inv.length, 3);
  for (const i of inv) {
    assert.equal(i.sponsor, `ticket:${tid}`);
    assert.deepEqual(i.audiences, ['members']); // not docs, not eidoverse, whatever `always` says
    assert.deepEqual([...i.scopes].sort(), ['members:member']); // docs:use is baseline but not allowed for tickets
    assert.deepEqual(i.claims, { tier: 'sponsored', sponsor: `ticket:${tid}`, sponsorName: 'Bea' });
  }
  // signing in moves nothing but the budget stays one pool: still full
  await emailLogin('b@example.org', 'members');
  const bsub = node.accounts.byEmail('b@example.org')!.sub;
  assert.deepEqual((await api('POST', '/tickets/invites', { email: 'b@example.org' })).body, { error: 'budget', reason: 'active' });
  assert.equal((await api('GET', '/tickets/invites?email=b%40example.org')).body.invites.length, 3);
  // an agent enrols: the budget frees one; what it gets is the ticket's reach
  const a = await enrol(inv[0]!.code, 'bea-agent');
  assert.equal(a.status, 200, JSON.stringify(a.body));
  for (const [aud, want] of [['members', 200], ['docs', 403], ['eidoverse', 403], ['gate', 403]] as const) {
    assert.equal((await raw('POST', '/token', makeTokenRequest(a.key.privateKey, a.key.id, 'id.test', aud))).status, want, aud);
  }
  const fourth = await api('POST', '/tickets/invites', { email: 'b@example.org', agentName: 'four' });
  assert.equal(fourth.status, 201);
  assert.equal(node.invites.all().find((i) => i.code === fourth.body.code)!.sponsor, bsub);
  // lifetime: five ever for this ticket (claimed or not, revoked or not)
  await api('DELETE', '/tickets/invites/' + fourth.body.code);
  assert.equal((await api('POST', '/tickets/invites', { email: 'b@example.org' })).status, 201); // the fifth
  assert.equal(node.tickets.byId(tid)!.invitesMinted, 5);
  assert.deepEqual((await api('POST', '/tickets/invites', { email: 'b@example.org' })).body, { error: 'budget', reason: 'lifetime' });
  // two admin tickets: two placeholders, two budgets, two listings
  node.tickets.add({ email: 'adm1@example.org', source: 'admin:x', audiences: ['members'], scopes: ['members:member'], name: 'Alice' });
  node.tickets.add({ email: 'adm2@example.org', source: 'admin:x', audiences: ['members'], scopes: ['members:member'], name: 'Bob' });
  const a1 = await api('POST', '/tickets/invites', { email: 'adm1@example.org', agentName: 'alice-agent' });
  assert.equal(a1.status, 201);
  assert.deepEqual((await api('GET', '/tickets/invites?email=adm2%40example.org')).body.invites, []);
  const t1 = node.tickets.byEmail('adm1@example.org')!.id;
  const t2 = node.tickets.byEmail('adm2@example.org')!.id;
  assert.notEqual(t1, t2);
  assert.equal(node.invites.all().find((i) => i.code === a1.body.code)!.sponsor, `ticket:${t1}`);
  for (let i = 0; i < 3; i++) assert.equal((await api('POST', '/tickets/invites', { email: 'adm2@example.org' })).status, 201);
  assert.equal((await api('POST', '/tickets/invites', { email: 'adm2@example.org' })).status, 409);
  assert.equal((await api('GET', '/tickets/invites?email=adm2%40example.org')).body.invites.length, 3);
  // email and ref must name the same ticket
  await api('POST', '/tickets', { email: 'mine@example.org', ref: 'MINE' });
  await api('POST', '/tickets', { email: 'victim2@example.org', ref: 'VIC', name: 'Victim' });
  assert.deepEqual((await api('POST', '/tickets/invites', { email: 'victim2@example.org', ref: 'MINE' })).body, { error: 'no_ticket' });
  assert.deepEqual((await api('POST', '/tickets/invites', { email: 'nobody@example.org', ref: 'MINE' })).body, { error: 'no_ticket' });
  assert.equal((await api('POST', '/tickets/invites', { email: 'mine@example.org', ref: 'MINE' })).status, 201);
  assert.equal((await api('POST', '/tickets/invites', { ref: 'VIC' })).status, 201);
  assert.equal((await api('GET', '/tickets/invites?ref=VIC')).body.invites.length, 1);
  assert.equal((await api('GET', '/tickets/invites?email=mine%40example.org&ref=VIC')).status, 404);
  // withhold on the account holds; operator scopes on the account are not passed on
  await api('POST', '/tickets', { email: 'wh@example.org', ref: 'WH' });
  await emailLogin('wh@example.org', 'members');
  node.accounts.update(node.accounts.byEmail('wh@example.org')!.sub, (x) => ({ ...x, withhold: ['members:member'], scopes: ['worlds:join'] }));
  const whi = await api('POST', '/tickets/invites', { email: 'wh@example.org' });
  assert.equal(whi.status, 403); // nothing left to carry: no audience
  // DELETE /tickets/invites/<code>: only unclaimed, only a ticket's
  assert.equal((await api('DELETE', '/tickets/invites/' + inv[0]!.code)).status, 404); // claimed
  assert.equal((await api('DELETE', '/tickets/invites/inv_nope')).status, 404);
  const plain = node.invites.mint({ scopes: [], maxUses: 1 });
  assert.equal((await api('DELETE', '/tickets/invites/' + plain.code)).status, 404); // not a ticket's
  assert.equal((await api('DELETE', '/tickets/invites/' + a1.body.code)).status, 204);
  assert.equal(node.invites.all().find((i) => i.code === a1.body.code), undefined);
});

test('small things: bearer spellings, token length, invisible characters, names, bursts, GET /enroll, 503 wording', async () => {
  // (a trailing space is not a case: fetch trims header values before they leave)
  for (const [auth, want] of [[`bearer ${TOKEN}`, 200], [`BEARER ${TOKEN}`, 200], [`Bearer  ${TOKEN}`, 401], [`Basic ${TOKEN}`, 401], [`Bearer ${TOKEN}x`, 401]] as const) {
    assert.equal((await raw('GET', '/tickets/x%40y.co', undefined, { authorization: auth })).status, want, auth.replace(TOKEN, 'T'));
  }
  assert.throws(() => makeNode({ ticketsToken: 'x'.repeat(31) }), /at least 32/);
  assert.doesNotThrow(() => makeNode({ ticketsToken: 'x'.repeat(32) }));
  // what the ticket site sends is cleaned of controls, C1, bidi overrides and separators
  const r = await api('POST', '/tickets', { email: 'cc@example.org', ref: 'cc\u0000\u001b[2J\u009b2J‮', name: 'Pat\u0000\u001b[31m\u0007\u009b‮RED⁦ X', note: 'n\u0001o\u001bte ' });
  assert.equal(r.status, 201);
  const t = node.tickets.byEmail('cc@example.org')!;
  assert.equal(t.source, 'api:cc[2J2J');
  assert.equal(t.name, 'Pat[31mRED X');
  assert.equal(t.note, 'note');
  // names: taken, reserved, an address, the default — fall back, and the body says so
  await node.accounts.add({ sub: 'human:local:antra', username: 'antra', password: await hashPassword('antra password 1'), createdAt: '' });
  for (const [email, name] of [['imp1@example.org', 'antra'], ['imp2@example.org', 'admin'], ['imp3@example.org', 'Antra'], ['imp4@example.org', 'x@y.com'], ['imp5@example.org', 'Ticket holder']]) {
    const m = await api('POST', '/tickets', { email, ref: `n-${email}`, name });
    assert.equal(m.status, 201);
    assert.equal(m.body.nameAccepted, false, name);
    assert.equal(node.tickets.byEmail(email!)!.name, undefined);
    const f = await emailLogin(email!, 'members');
    const v = verifyToken(tokOf(f.body.redirect)!, { issuerId: node.issuer.id, iss: 'id.test', aud: 'members' });
    assert.equal(v.ok && v.payload.name, 'Ticket holder', name);
  }
  const good = await api('POST', '/tickets', { email: 'ok-name@example.org', ref: 'n-ok', name: 'Okay Name' });
  assert.equal(good.body.nameAccepted, true);
  // the ticket site's own burst from one address
  const ip = { 'x-real-ip': '203.0.113.200' };
  const st: number[] = [];
  for (let i = 0; i < 40; i++) st.push((await api('POST', '/tickets', { email: `burst${i}@example.org`, ref: `BU${i}` }, ip)).status);
  assert.ok(st.every((s) => s === 201));
  // GET /enroll is a page, not a 404
  const en = await raw('GET', '/enroll');
  assert.equal(en.status, 200);
  assert.match(en.body, /agents\.md/);
  // 503 says whether the defaults file is missing or refused
  const n2 = makeNode({}, null);
  const b2 = `http://127.0.0.1:${await n2.start()}`;
  try {
    const miss = await api('POST', '/tickets', { email: 'x@example.org', ref: 'rx' }, {}, b2);
    assert.equal(miss.status, 503);
    assert.match(miss.body.error, /copy config\/ticket-defaults\.example\.json/);
    writeFileSync(join(n2.cfg.configDir, 'ticket-defaults.json'), '{ "audiences": ["console"], "scopes": [] }');
    n2.ticketDefaults.refresh();
    const bad = await api('POST', '/tickets', { email: 'x@example.org', ref: 'rx' }, {}, b2);
    assert.equal(bad.status, 503);
    assert.match(bad.body.error, /present but refused/);
    assert.doesNotMatch(bad.body.error, /copy/);
  } finally {
    n2.stop();
  }
});
