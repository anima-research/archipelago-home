import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { clean, maskEmail, ticketDefaultsProblem, ticketDefaultsStore, ticketGrantProblem, ticketsProblem, TicketStore, usableEmail } from '../src/tickets.js';
import { emailSenderFromConfig, logSender, signInCodeMessage } from '../src/email.js';

const fresh = () => mkdtempSync(join(tmpdir(), 'hn-tickets-'));

test('tickets: one per mailbox — Gmail dots and +suffix, and case, are the same ticket; stored as typed', () => {
  const dir = fresh();
  const store = new TicketStore(join(dir, 'tickets.json'));
  const a = store.add({ email: 'Jo.Anne+coev@GMail.com', source: 'admin:test', audiences: ['members'], scopes: ['members:member'], note: 'x' });
  assert.equal(a.created, true);
  assert.equal(a.ticket.email, 'Jo.Anne+coev@GMail.com');
  assert.equal(a.ticket.note, 'x');
  const again = store.add({ email: 'joanne@googlemail.com', source: 'api:ref-1', audiences: [], scopes: [] });
  assert.equal(again.created, false);
  assert.equal(again.ticket.source, 'admin:test'); // the first one stands
  assert.equal(store.all().length, 1);
  assert.ok(store.byEmail('JOANNE@gmail.com'));
  assert.equal(store.byEmail('jo.anne@example.org'), undefined);
  // other domains keep dots and +: a different mailbox
  store.add({ email: 'jo.anne+x@example.org', source: 'admin:test', audiences: ['members'], scopes: [] });
  assert.equal(store.byEmail('joanne@example.org'), undefined);
  assert.ok(store.byEmail('Jo.Anne+x@Example.org'));
  assert.equal((statSync(join(dir, 'tickets.json')).mode & 0o777), 0o600);
  assert.throws(() => store.add({ email: 'not-an-address', source: 'admin:test', audiences: [], scopes: [] }));
  // printable ASCII only: a look-alike that keys the same must not be mailed instead
  assert.throws(() => store.add({ email: '\u212Aim@example.org', source: 'admin:test', audiences: [], scopes: [] }));
  assert.equal(usableEmail('kim@example.org'), true);
  assert.equal(usableEmail('\u212Aim@example.org'), false);
  assert.equal(usableEmail('k im@example.org'), false);
  assert.equal(clean(' a\u0000b\nc ', 10), 'abc');
  assert.equal(clean('a\u0085b\u202ec\u2066d\u2028e', 10), 'abcde'); // C1, bidi override, isolate, line separator
  assert.equal(clean('x'.repeat(20), 5), 'xxxxx');
  assert.equal(clean(7, 5), '');
});

test('tickets: claim is first-come and sticks; remove keeps nothing; refs find the ticket they were recorded on', () => {
  const dir = fresh();
  const store = new TicketStore(join(dir, 'tickets.json'));
  store.add({ email: 'a@example.org', source: 'api:ref-a', audiences: ['members'], scopes: ['members:member'] });
  assert.equal(store.claim('A@example.org', 'human:email:one')!.claimedBy, 'human:email:one');
  assert.equal(store.claim('a@example.org', 'human:email:two'), undefined); // someone else's now
  assert.equal(store.claim('a@example.org', 'human:email:one')!.claimedBy, 'human:email:one'); // idempotent
  assert.equal(store.claim('nobody@example.org', 'human:email:one'), undefined);
  assert.ok(store.byEmail('a@example.org')!.claimedAt);
  assert.equal(store.byRef('ref-a')!.email, 'a@example.org');
  assert.equal(store.byRef('ref-b'), undefined);
  assert.deepEqual(store.addRef('A@example.org', 'ref-b')!.refs, ['ref-b']);
  assert.deepEqual(store.addRef('a@example.org', 'ref-b')!.refs, ['ref-b']); // known: no-op
  assert.deepEqual(store.addRef('a@example.org', 'ref-a')!.refs, ['ref-b']); // the source ref: no-op
  assert.equal(store.byRef('ref-b')!.email, 'a@example.org');
  assert.equal(store.addRef('nobody@example.org', 'r'), undefined);
  // a second purchase widens the grant (never narrows) and names an unnamed holder
  const widened = store.addRef('a@example.org', 'ref-c', { audiences: ['members', 'extra'], scopes: [], name: 'Ann' })!;
  assert.deepEqual([widened.audiences, widened.scopes, widened.name], [['members', 'extra'], ['members:member'], 'Ann']);
  assert.equal(store.addRef('a@example.org', 'ref-d', { name: 'Other' })!.name, 'Ann');
  // removal keeps the ticket under `removed`: every ref that reached it is spent, and it can still be looked up
  const id = store.byEmail('a@example.org')!.id;
  assert.match(id, /^tk_[0-9a-f]{12}$/);
  assert.equal(store.remove('a@example.org')!.email, 'a@example.org');
  assert.equal(store.remove('a@example.org'), undefined);
  assert.equal(store.byEmail('a@example.org'), undefined);
  assert.equal(store.byId(id), undefined);
  for (const r of ['ref-a', 'ref-b', 'ref-c', 'ref-d']) assert.equal(store.removed(r), true, r);
  assert.equal(store.removed('ref-z'), false);
  assert.equal(store.removedTicket({ email: 'A@example.org' })!.id, id);
  assert.equal(store.removedTicket({ ref: 'ref-c' })!.id, id);
  assert.ok(store.removedTicket({ ref: 'ref-c' })!.removedAt);
  const onDisk = JSON.parse(readFileSync(join(dir, 'tickets.json'), 'utf8'));
  assert.deepEqual(onDisk.tickets, []);
  assert.equal(onDisk.removed.length, 1);
  // an admin ticket has no api ref, only recorded ones
  store.add({ email: 'b@example.org', source: 'admin:x', audiences: ['members'], scopes: [] });
  store.addRef('b@example.org', 'ref-e');
  store.remove('b@example.org');
  assert.equal(store.removed('ref-e'), true);
  assert.equal(store.removed('admin:x'), false);
});

test('tickets: a malformed file is refused (duplicate mailbox, bad shape)', () => {
  assert.equal(ticketsProblem({ tickets: [] }), null);
  const row = (x: Record<string, unknown>) => ({ id: 'tk_1', email: 'a@b.co', source: 's', addedAt: 't', audiences: [], scopes: [], ...x });
  assert.match(ticketsProblem({ tickets: [row({ audiences: ['x'] }), row({ id: 'tk_2', email: 'A@B.CO' })] })!, /two tickets/);
  assert.match(ticketsProblem({ tickets: [row({}), row({ email: 'c@d.co' })] })!, /id tk_1/);
  assert.match(ticketsProblem({ tickets: [row({ id: undefined })] })!, /without an id/);
  assert.match(ticketsProblem({ tickets: [row({ email: 'nope' })] })!, /email/);
  assert.match(ticketsProblem({ tickets: [row({ audiences: [7] })] })!, /audiences/);
  assert.match(ticketsProblem({ tickets: [row({ refs: 'x' })] })!, /refs/);
  assert.match(ticketsProblem({ tickets: [], removed: [{ id: 'x' }] })!, /removed/);
  assert.equal(ticketsProblem({ tickets: [row({})], removed: [{ ...row({ id: 'tk_9' }), removedAt: 't' }] }), null);
  assert.match(ticketsProblem({ tickets: {} })!, /not a tickets file/);
  const dir = fresh();
  writeFileSync(join(dir, 'tickets.json'), '{ nope');
  assert.deepEqual(new TicketStore(join(dir, 'tickets.json')).all(), []);
});

test('ticket defaults (config/ticket-defaults.json): strict, hot-reloadable, absent = nothing; the allowlist bounds every ticket', async () => {
  assert.equal(ticketDefaultsProblem({ audiences: ['members'], scopes: ['members:member'], _: 'note' }), null);
  assert.equal(ticketDefaultsProblem({ audiences: ['members'], scopes: [], allowed: { audiences: ['members', 'extra'], scopes: ['x:y'], _: 'c' } }), null);
  assert.match(ticketDefaultsProblem({ audiences: ['members'], scopes: ['members:member'], audience: [] })!, /unknown key "audience"/);
  assert.match(ticketDefaultsProblem({ audiences: 'members', scopes: [] })!, /audiences/);
  assert.match(ticketDefaultsProblem({ audiences: [], scopes: [] })!, /non-empty/);
  assert.match(ticketDefaultsProblem({ audiences: ['members'], scopes: [''] })!, /scopes/);
  assert.match(ticketDefaultsProblem({ audiences: ['console'], scopes: [] })!, /this node’s own/);
  assert.match(ticketDefaultsProblem({ audiences: ['members'], scopes: [], allowed: [] })!, /allowed must be an object/);
  assert.match(ticketDefaultsProblem({ audiences: ['members'], scopes: [], allowed: { audiences: ['members'], scopes: [], scoeps: [] } })!, /allowed\.scoeps/);
  assert.match(ticketDefaultsProblem({ audiences: ['members'], scopes: [], allowed: { audiences: ['account'], scopes: [] } })!, /this node’s own/);
  assert.match(ticketDefaultsProblem({ audiences: ['members'], scopes: ['a:b'], allowed: { audiences: ['members'], scopes: [] } })!, /"a:b" is not in allowed/);
  assert.match(ticketDefaultsProblem({ audiences: ['members'], scopes: ['id:anchor'] })!, /id:\*/);
  assert.match(ticketDefaultsProblem({ audiences: ['members'], scopes: [], allowed: { audiences: ['members'], scopes: ['id:anchor'] } })!, /id:\*/);
  assert.match(ticketDefaultsProblem({ audiences: ['members'], scopes: [], invites: [] })!, /invites must be an object/);
  assert.match(ticketDefaultsProblem({ audiences: ['members'], scopes: [], invites: { active: 3, lifetime: 2 } })!, /exceed/);
  assert.match(ticketDefaultsProblem({ audiences: ['members'], scopes: [], invites: { active: '3', lifetime: 10 } })!, /whole numbers/);
  assert.match(ticketDefaultsProblem({ audiences: ['members'], scopes: [], invites: { active: 3, lifetime: 10, x: 1 } })!, /invites\.x/);
  assert.equal(ticketDefaultsProblem({ audiences: ['members'], scopes: [], invites: { active: 1, lifetime: 1 } }), null);
  assert.match(ticketDefaultsProblem([])!, /not an object/);
  // the one check behind POST /tickets and hn ticket add
  const d = { configured: true, audiences: ['members'], scopes: ['members:member'], allowed: { audiences: ['members', 'extra'], scopes: ['members:member', 'extra:use'] } };
  const known = ['members', 'extra', 'eidoverse'];
  assert.equal(ticketGrantProblem(d, known, ['members', 'extra'], ['extra:use']), null);
  assert.match(ticketGrantProblem({ ...d, configured: false }, known, ['members'], [])!, /no config/);
  assert.match(ticketGrantProblem(d, known, [], [])!, /at least one audience/);
  assert.match(ticketGrantProblem(d, known, ['console'], [])!, /this node’s own/);
  assert.match(ticketGrantProblem(d, known, ['account'], [])!, /this node’s own/);
  assert.match(ticketGrantProblem(d, known, ['eidoverse'], [])!, /not one a ticket may carry/);
  assert.match(ticketGrantProblem(d, ['members'], ['extra'], [])!, /no audience "extra" in audiences\.json/);
  assert.match(ticketGrantProblem(d, known, ['members'], ['worlds:join'])!, /scope "worlds:join"/);
  assert.match(ticketGrantProblem({ ...d, allowed: { ...d.allowed, scopes: ['id:anchor'] } }, known, ['members'], ['id:anchor'])!, /own authority/);
  const dir = fresh();
  const path = join(dir, 'ticket-defaults.json');
  assert.equal(ticketDefaultsStore(path).get().configured, false);
  writeFileSync(path, JSON.stringify({ audiences: ['members'], scopes: ['members:member'] }));
  const store = ticketDefaultsStore(path);
  // allowed defaults to the defaults; the invite budget to 3 active / 10 ever
  assert.deepEqual(store.get(), {
    configured: true, audiences: ['members'], scopes: ['members:member'], allowed: { audiences: ['members'], scopes: ['members:member'] }, invites: { active: 3, lifetime: 10 },
  });
  store.startWatching(20);
  try {
    writeFileSync(path, JSON.stringify({ audiences: ['members'], scoeps: [] }));
    await new Promise((r) => setTimeout(r, 120));
    assert.deepEqual(store.get().scopes, ['members:member']); // the typo'd file was refused
  } finally {
    store.stopWatching();
  }
});

test('email: masking, the message, and which sender the environment picks', async () => {
  assert.equal(maskEmail('alice@example.org'), 'a***@example.org');
  assert.equal(maskEmail('nope'), '***');
  const m = signInCodeMessage('123456');
  assert.equal(m.text, "Your sign-in code is 123456. It expires in 10 minutes. If you didn't request this, ignore it.");
  assert.equal(emailSenderFromConfig({ publicUrl: 'https://id.test' }), null);
  assert.equal(emailSenderFromConfig({ publicUrl: 'https://id.test', emailProvider: '' }), null);
  assert.throws(() => emailSenderFromConfig({ publicUrl: 'https://id.test', emailProvider: 'log' }), /not for a public https/);
  assert.ok(emailSenderFromConfig({ publicUrl: 'http://127.0.0.1:7360', emailProvider: 'log' }));
  assert.throws(() => emailSenderFromConfig({ publicUrl: 'https://id.test', emailProvider: 'resend' }), /RESEND_API_KEY/);
  assert.throws(() => emailSenderFromConfig({ publicUrl: 'https://id.test', emailProvider: 'resend', resendApiKey: 'k' }), /EMAIL_FROM/);
  assert.throws(() => emailSenderFromConfig({ publicUrl: 'https://id.test', emailProvider: 'pigeon' }), /unknown/);
  // resend: one HTTPS POST with the key, from, to, subject and text
  let seen: { url: string; init: RequestInit } | null = null;
  const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
    seen = { url: String(url), init: init! };
    return new Response('{"id":"x"}', { status: 200 });
  }) as typeof fetch;
  const resend = emailSenderFromConfig({ publicUrl: 'https://id.test', emailProvider: 'resend', resendApiKey: 're_k', emailFrom: 'Home <no-reply@id.test>' }, fetchImpl)!;
  await resend.send('to@example.org', 'subj', 'body');
  assert.equal(seen!.url, 'https://api.resend.com/emails');
  assert.equal((seen!.init.headers as Record<string, string>).authorization, 'Bearer re_k');
  assert.deepEqual(JSON.parse(String(seen!.init.body)), { from: 'Home <no-reply@id.test>', to: ['to@example.org'], subject: 'subj', text: 'body' });
  const failing = emailSenderFromConfig({ publicUrl: 'https://id.test', emailProvider: 'resend', resendApiKey: 'k', emailFrom: 'f' },
    (async () => new Response('nope', { status: 403 })) as typeof fetch)!;
  await assert.rejects(failing.send('a@b.co', 's', 't'), /resend: 403/);
  // log: the whole message, to the log
  const lines: string[] = [];
  await logSender((l) => lines.push(l)).send('a@b.co', m.subject, m.text);
  assert.match(lines[0]!, /a@b\.co[\s\S]*123456/);
});
