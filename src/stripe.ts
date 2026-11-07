/**
 * The Stripe webhook, without the Stripe SDK (this package has no runtime
 * dependencies, and needs one check): the `Stripe-Signature` header is
 * `t=<unix s>,v1=<hex hmac>[,v1=…]`, the HMAC-SHA256 under the endpoint's
 * signing secret of `<t>.<raw body>`. A good signature on a stale timestamp
 * is a replay, so `t` must be within the tolerance (Stripe's own default,
 * five minutes). Idempotency is the event id (tickets.ts).
 *
 * What a successful payment tells us is just the address it was made with:
 * that address gets a ticket (tickets.ts). Nothing else about the payment is
 * kept.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';

export const STRIPE_TOLERANCE_S = 300;

export type StripeCheck = { ok: true } | { ok: false; reason: string };

export function verifyStripeSignature(rawBody: string, header: string | undefined, secret: string, nowS = Math.floor(Date.now() / 1000), toleranceS = STRIPE_TOLERANCE_S): StripeCheck {
  if (!header) return { ok: false, reason: 'no Stripe-Signature header' };
  let t: number | null = null;
  const sigs: string[] = [];
  for (const part of header.split(',')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k === 't' && /^\d+$/.test(v)) t = Number(v);
    else if (k === 'v1' && /^[0-9a-f]+$/i.test(v)) sigs.push(v.toLowerCase());
  }
  if (t === null) return { ok: false, reason: 'no timestamp' };
  if (!sigs.length) return { ok: false, reason: 'no v1 signature' };
  const want = createHmac('sha256', secret).update(`${t}.${rawBody}`, 'utf8').digest();
  const good = sigs.some((s) => {
    const got = Buffer.from(s, 'hex');
    return got.length === want.length && timingSafeEqual(got, want);
  });
  if (!good) return { ok: false, reason: 'signature mismatch' };
  if (Math.abs(nowS - t) > toleranceS) return { ok: false, reason: 'timestamp outside tolerance' };
  return { ok: true };
}

/** For tests and tooling: the header Stripe would send for this body. */
export function signStripePayload(rawBody: string, secret: string, t = Math.floor(Date.now() / 1000)): string {
  return `t=${t},v1=${createHmac('sha256', secret).update(`${t}.${rawBody}`, 'utf8').digest('hex')}`;
}

export interface StripeEvent {
  id: string;
  type: string;
  data?: { object?: Record<string, unknown> };
}

/** The event, if it is shaped like one. */
export function parseStripeEvent(rawBody: string): StripeEvent | null {
  let e: unknown;
  try {
    e = JSON.parse(rawBody);
  } catch {
    return null;
  }
  const ev = e as StripeEvent;
  if (!ev || typeof ev !== 'object' || typeof ev.id !== 'string' || !ev.id || typeof ev.type !== 'string') return null;
  return ev;
}

const TICKET_EVENTS = new Set(['checkout.session.completed', 'payment_intent.succeeded']);

/**
 * The address a paid event was made with, or null when the event isn't one
 * that earns a ticket, or carries no address (a payment intent made without
 * one — nothing to send a code to, so nothing to do).
 */
export function ticketEmailFromEvent(ev: StripeEvent): string | null {
  if (!TICKET_EVENTS.has(ev.type)) return null;
  const o = ev.data?.object ?? {};
  const details = o.customer_details as { email?: unknown } | undefined;
  const candidates = [details?.email, o.customer_email, o.receipt_email];
  for (const c of candidates) if (typeof c === 'string' && c.trim()) return c.trim();
  return null;
}
