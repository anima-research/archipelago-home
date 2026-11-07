import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseStripeEvent, signStripePayload, ticketEmailFromEvent, verifyStripeSignature } from '../src/stripe.js';

const SECRET = 'whsec_test_secret';
const NOW = 1_800_000_000;
const body = JSON.stringify({ id: 'evt_1', type: 'checkout.session.completed', data: { object: { customer_details: { email: 'a@b.co' } } } });

test('stripe signature: the v1 HMAC over "t.body", within five minutes', () => {
  const header = signStripePayload(body, SECRET, NOW);
  assert.match(header, /^t=1800000000,v1=[0-9a-f]{64}$/);
  assert.deepEqual(verifyStripeSignature(body, header, SECRET, NOW), { ok: true });
  assert.deepEqual(verifyStripeSignature(body, header, SECRET, NOW + 299), { ok: true });
  assert.deepEqual(verifyStripeSignature(body, header, SECRET, NOW - 300), { ok: true });
  // stale, or from the future: a replay
  assert.match((verifyStripeSignature(body, header, SECRET, NOW + 301) as { reason: string }).reason, /tolerance/);
  assert.match((verifyStripeSignature(body, header, SECRET, NOW - 301) as { reason: string }).reason, /tolerance/);
  // wrong secret, tampered body, tampered timestamp, garbage
  assert.match((verifyStripeSignature(body, header, 'whsec_other', NOW) as { reason: string }).reason, /mismatch/);
  assert.match((verifyStripeSignature(body + ' ', header, SECRET, NOW) as { reason: string }).reason, /mismatch/);
  assert.match((verifyStripeSignature(body, header.replace('t=1800000000', 't=1800000001'), SECRET, NOW) as { reason: string }).reason, /mismatch/);
  assert.match((verifyStripeSignature(body, undefined, SECRET, NOW) as { reason: string }).reason, /no Stripe-Signature/);
  assert.match((verifyStripeSignature(body, 'v1=abcd', SECRET, NOW) as { reason: string }).reason, /timestamp/);
  assert.match((verifyStripeSignature(body, `t=${NOW}`, SECRET, NOW) as { reason: string }).reason, /v1/);
  assert.match((verifyStripeSignature(body, `t=${NOW},v1=zz`, SECRET, NOW) as { reason: string }).reason, /v1/);
  // several v1 signatures (a secret rotation): any good one passes
  const old = signStripePayload(body, 'whsec_old', NOW).split(',')[1];
  assert.deepEqual(verifyStripeSignature(body, `${header},${old}`, 'whsec_old', NOW), { ok: true });
  assert.deepEqual(verifyStripeSignature(body, `${old},${header.split(',')[1]},t=${NOW}`, SECRET, NOW), { ok: true });
});

test('stripe event: which events earn a ticket, and the address they carry', () => {
  assert.equal(parseStripeEvent('{'), null);
  assert.equal(parseStripeEvent('{"type":"x"}'), null);
  assert.equal(parseStripeEvent('[]'), null);
  const ev = parseStripeEvent(body)!;
  assert.equal(ev.id, 'evt_1');
  assert.equal(ticketEmailFromEvent(ev), 'a@b.co');
  const mk = (type: string, object: Record<string, unknown>) => ({ id: 'e', type, data: { object } });
  assert.equal(ticketEmailFromEvent(mk('checkout.session.completed', { customer_email: ' B@c.co ' })), 'B@c.co');
  assert.equal(ticketEmailFromEvent(mk('checkout.session.completed', { customer_details: { email: null }, customer_email: 'c@d.co' })), 'c@d.co');
  assert.equal(ticketEmailFromEvent(mk('checkout.session.completed', {})), null);
  assert.equal(ticketEmailFromEvent(mk('payment_intent.succeeded', { receipt_email: 'r@s.co' })), 'r@s.co');
  assert.equal(ticketEmailFromEvent(mk('payment_intent.succeeded', { amount: 1 })), null);
  assert.equal(ticketEmailFromEvent(mk('customer.created', { email: 'x@y.co' })), null);
  assert.equal(ticketEmailFromEvent({ id: 'e', type: 'checkout.session.completed' }), null);
});
