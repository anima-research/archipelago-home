/**
 * Tickets: addresses entitled to make an account by email alone (human.ts,
 * `/login/email/*`). A ticket arrives from the ticket site (`POST /tickets`,
 * server.ts — it has verified the payment; this node never talks to a
 * payment provider) or the operator (`hn ticket add`), and says what the
 * account it makes holds: `audiences` + `scopes`, defaulting to
 * config/ticket-defaults.json.
 *
 * One ticket = one account: the first email sign-up with the address claims
 * it (`claimedBy`), and a later sign-in with the same address opens that
 * account. The grant is COPIED onto the row when claimed (accounts.ts
 * `ticket`), so `hn ticket rm` only stops future sign-ups — an account that
 * already exists keeps what it was given (disable it with `hn user disable`).
 *
 * Addresses are matched the way mail is delivered (google.ts emailKey: case,
 * and for Gmail dots and +suffix), but stored as typed.
 *
 * data/tickets.json is 0600 like codes.json: it is a list of customers.
 * (The defaults file is config/ticket-defaults.json — a different name, so
 * a deployment whose data and config dirs coincide can't mix them up.)
 */
import { JsonStore } from './stores.js';
import { emailKey, looksLikeEmail } from './google.js';

export interface Ticket {
  /** As typed / as the ticket site sent it; matching is by emailKey. */
  email: string;
  /** `api:<ref>` (the ticket site's reference) or `admin:<who>`. */
  source: string;
  /** Further refs the ticket site sent for the same mailbox (a second
   *  purchase): recorded, so each ref answers idempotently. */
  refs?: string[];
  addedAt: string;
  audiences: string[];
  scopes: string[];
  note?: string;
  /** The account the first email sign-up made (or linked) with it. */
  claimedBy?: string;
  claimedAt?: string;
}

export interface TicketsFile {
  tickets: Ticket[];
}

export function ticketsProblem(raw: unknown): string | null {
  const f = raw as TicketsFile;
  if (!f || typeof f !== 'object' || !Array.isArray(f.tickets)) return 'not a tickets file';
  const strings = (v: unknown) => Array.isArray(v) && v.every((s) => typeof s === 'string' && s.length > 0);
  const keys = new Set<string>();
  for (const t of f.tickets) {
    if (!t || typeof t.email !== 'string' || !looksLikeEmail(t.email)) return 'bad ticket email';
    const k = emailKey(t.email);
    if (keys.has(k)) return `two tickets for ${t.email}`;
    keys.add(k);
    if (typeof t.source !== 'string' || typeof t.addedAt !== 'string') return `bad ticket for ${t.email}`;
    if (!strings(t.audiences) || !strings(t.scopes)) return `bad audiences/scopes on the ticket for ${t.email}`;
    if (t.claimedBy !== undefined && typeof t.claimedBy !== 'string') return `bad claimedBy on the ticket for ${t.email}`;
    if (t.refs !== undefined && !strings(t.refs)) return `bad refs on the ticket for ${t.email}`;
  }
  return null;
}

function validate(raw: unknown): TicketsFile | null {
  if (ticketsProblem(raw)) return null;
  return { tickets: (raw as TicketsFile).tickets };
}

export class TicketStore {
  private store: JsonStore<TicketsFile>;

  constructor(path: string) {
    this.store = new JsonStore(path, validate, { tickets: [] }, 'tickets', 0o600);
  }
  startWatching(): void {
    this.store.startWatching();
  }
  stopWatching(): void {
    this.store.stopWatching();
  }

  /** Always current: picks up an `hn ticket …` edit made a moment ago. */
  all(): Ticket[] {
    this.store.refresh();
    return this.store.get().tickets;
  }

  byEmail(email: string): Ticket | undefined {
    const k = emailKey(email);
    return this.all().find((t) => emailKey(t.email) === k);
  }

  /** The ticket the ticket site's reference made, or was recorded on. */
  byRef(ref: string): Ticket | undefined {
    return this.all().find((t) => t.source === `api:${ref}` || t.refs?.includes(ref));
  }

  /**
   * Add a ticket for an address; one that already holds a ticket is left as
   * it is (`created: false`) — a redelivered webhook or a repeated purchase
   * doesn't make a second one.
   */
  add(t: Omit<Ticket, 'addedAt'>, nowMs = Date.now()): { ticket: Ticket; created: boolean } {
    if (!looksLikeEmail(t.email)) throw new Error(`not an email address: ${t.email}`);
    const k = emailKey(t.email);
    let out: { ticket: Ticket; created: boolean } | undefined;
    this.store.update((f) => {
      const existing = f.tickets.find((x) => emailKey(x.email) === k);
      if (existing) {
        out = { ticket: existing, created: false };
        return f;
      }
      const ticket: Ticket = { ...t, email: t.email.trim(), addedAt: new Date(nowMs).toISOString() };
      out = { ticket, created: true };
      return { ...f, tickets: [...f.tickets, ticket] };
    });
    return out!;
  }

  /** Note a further reference on the mailbox's existing ticket (no-op if known). */
  addRef(email: string, ref: string): Ticket | undefined {
    const k = emailKey(email);
    let out: Ticket | undefined;
    this.store.update((f) => {
      const t = f.tickets.find((x) => emailKey(x.email) === k);
      if (!t) return f;
      if (t.source === `api:${ref}` || t.refs?.includes(ref)) {
        out = t;
        return f;
      }
      out = { ...t, refs: [...(t.refs ?? []), ref] };
      return { ...f, tickets: f.tickets.map((x) => (x === t ? out! : x)) };
    });
    return out;
  }

  /** Remove the entitlement; nothing happens to an account it already made. */
  remove(email: string): Ticket | undefined {
    const k = emailKey(email);
    let out: Ticket | undefined;
    this.store.update((f) => {
      out = f.tickets.find((x) => emailKey(x.email) === k);
      return out ? { ...f, tickets: f.tickets.filter((x) => x !== out) } : f;
    });
    return out;
  }

  /** Record which account took the ticket up; a ticket already claimed by
   *  another account is left alone (returns undefined). */
  claim(email: string, sub: string, nowMs = Date.now()): Ticket | undefined {
    const k = emailKey(email);
    let out: Ticket | undefined;
    this.store.update((f) => {
      const t = f.tickets.find((x) => emailKey(x.email) === k);
      if (!t || (t.claimedBy && t.claimedBy !== sub)) return f;
      if (t.claimedBy === sub) {
        out = t;
        return f;
      }
      out = { ...t, claimedBy: sub, claimedAt: new Date(nowMs).toISOString() };
      return { ...f, tickets: f.tickets.map((x) => (x === t ? out! : x)) };
    });
    return out;
  }
}

// ── config/ticket-defaults.json: what a ticket grants unless told otherwise ──

export interface TicketDefaults {
  /** False for the built-in "no file" value: tickets grant nothing unless `hn ticket add` says what. */
  configured: boolean;
  audiences: string[];
  scopes: string[];
}

export const NO_TICKET_DEFAULTS: TicketDefaults = { configured: false, audiences: [], scopes: [] };

/** Strict like invite-policy.json: a typo refuses the file and the last good
 *  one stays, rather than silently granting nothing. Keys starting with "_" are comments. */
export function ticketDefaultsProblem(raw: unknown): string | null {
  const f = raw as Record<string, unknown>;
  if (!f || typeof f !== 'object' || Array.isArray(f)) return 'not an object';
  for (const k of Object.keys(f)) if (!k.startsWith('_') && k !== 'audiences' && k !== 'scopes') return `unknown key "${k}"`;
  const isStrings = (v: unknown) => Array.isArray(v) && v.every((s) => typeof s === 'string' && s.length > 0);
  if (!isStrings(f.audiences)) return 'audiences must be a list of audience names';
  if (!isStrings(f.scopes)) return 'scopes must be a list of scopes';
  return null;
}

export function ticketDefaultsStore(path: string): JsonStore<TicketDefaults> {
  return new JsonStore<TicketDefaults>(
    path,
    (raw) => {
      const bad = ticketDefaultsProblem(raw);
      if (bad) {
        console.error(`[hn] tickets: ${bad}`);
        return null;
      }
      const f = raw as { audiences: string[]; scopes: string[] };
      return { configured: true, audiences: f.audiences, scopes: f.scopes };
    },
    NO_TICKET_DEFAULTS,
    'ticket defaults',
  );
}

/** `a***@domain` — enough to recognise, not enough to mail. For logs. */
export function maskEmail(email: string): string {
  const at = email.indexOf('@');
  if (at < 1) return '***';
  return `${email[0]}***@${email.slice(at + 1)}`;
}
