import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { maskEmail, ticketDefaultsProblem, ticketDefaultsStore, ticketsProblem, TicketStore } from '../src/tickets.js';
import { emailSenderFromConfig, logSender, signInCodeMessage } from '../src/email.js';

const fresh = () => mkdtempSync(join(tmpdir(), 'hn-tickets-'));

test('tickets: one per mailbox — Gmail dots and +suffix, and case, are the same ticket; stored as typed', () => {
  const dir = fresh();
  const store = new TicketStore(join(dir, 'tickets.json'));
  const a = store.add({ email: 'Jo.Anne+coev@GMail.com', source: 'admin:test', audiences: ['members'], scopes: ['members:member'], note: 'x' });
  assert.equal(a.created, true);
  assert.equal(a.ticket.email, 'Jo.Anne+coev@GMail.com');
  assert.equal(a.ticket.note, 'x');
  const again = store.add({ email: 'joanne@googlemail.com', source: 'stripe:evt_1', audiences: [], scopes: [] });
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
});

test('tickets: claim is first-come and sticks; remove keeps nothing; a replayed Stripe event id is seen once', () => {
  const dir = fresh();
  const store = new TicketStore(join(dir, 'tickets.json'));
  store.add({ email: 'a@example.org', source: 'stripe:evt_a', audiences: ['members'], scopes: ['members:member'] });
  assert.equal(store.claim('A@example.org', 'human:email:one')!.claimedBy, 'human:email:one');
  assert.equal(store.claim('a@example.org', 'human:email:two'), undefined); // someone else's now
  assert.equal(store.claim('a@example.org', 'human:email:one')!.claimedBy, 'human:email:one'); // idempotent
  assert.equal(store.claim('nobody@example.org', 'human:email:one'), undefined);
  assert.ok(store.byEmail('a@example.org')!.claimedAt);
  assert.equal(store.remove('a@example.org')!.email, 'a@example.org');
  assert.equal(store.remove('a@example.org'), undefined);
  assert.equal(store.byEmail('a@example.org'), undefined);
  assert.equal(store.stripeEventOnce('evt_1'), true);
  assert.equal(store.stripeEventOnce('evt_1'), false);
  assert.equal(store.stripeEventOnce('evt_2'), true);
  assert.deepEqual(JSON.parse(readFileSync(join(dir, 'tickets.json'), 'utf8')).stripeEvents, ['evt_1', 'evt_2']);
});

test('tickets: a malformed file is refused (duplicate mailbox, bad shape)', () => {
  assert.equal(ticketsProblem({ tickets: [] }), null);
  assert.match(ticketsProblem({ tickets: [{ email: 'a@b.co', source: 's', addedAt: 't', audiences: ['x'], scopes: [] }, { email: 'A@B.CO', source: 's', addedAt: 't', audiences: [], scopes: [] }] })!, /two tickets/);
  assert.match(ticketsProblem({ tickets: [{ email: 'nope', source: 's', addedAt: 't', audiences: [], scopes: [] }] })!, /email/);
  assert.match(ticketsProblem({ tickets: [{ email: 'a@b.co', source: 's', addedAt: 't', audiences: [7], scopes: [] }] })!, /audiences/);
  assert.match(ticketsProblem({ tickets: {} })!, /not a tickets file/);
  const dir = fresh();
  writeFileSync(join(dir, 'tickets.json'), '{ nope');
  assert.deepEqual(new TicketStore(join(dir, 'tickets.json')).all(), []);
});

test('ticket defaults (config/ticket-defaults.json): strict, hot-reloadable, absent = nothing', async () => {
  assert.equal(ticketDefaultsProblem({ audiences: ['members'], scopes: ['members:member'], _: 'note' }), null);
  assert.match(ticketDefaultsProblem({ audiences: ['members'], scopes: ['members:member'], audience: [] })!, /unknown key "audience"/);
  assert.match(ticketDefaultsProblem({ audiences: 'members', scopes: [] })!, /audiences/);
  assert.match(ticketDefaultsProblem({ audiences: [], scopes: [''] })!, /scopes/);
  assert.match(ticketDefaultsProblem([])!, /not an object/);
  const dir = fresh();
  const path = join(dir, 'ticket-defaults.json');
  assert.equal(ticketDefaultsStore(path).get().configured, false);
  writeFileSync(path, JSON.stringify({ audiences: ['members'], scopes: ['members:member'] }));
  const store = ticketDefaultsStore(path);
  assert.deepEqual(store.get(), { configured: true, audiences: ['members'], scopes: ['members:member'] });
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
