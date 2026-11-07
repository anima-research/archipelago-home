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
 * `ticket`) and kept in step from here: a further purchase widens it, a
 * refund (`DELETE /tickets/<email>`, `hn ticket rm`: takeBackTicket) takes
 * it away again — from the account, from the agents its invites enrolled —
 * while the account itself stays. A refunded ticket is kept under `removed`
 * so a redelivered reference makes nothing and the site can still list it.
 *
 * Addresses are matched the way mail is delivered (google.ts emailKey: case,
 * and for Gmail dots and +suffix), but stored as typed.
 *
 * data/tickets.json is 0600 like codes.json: it is a list of customers.
 * (The defaults file is config/ticket-defaults.json — a different name, so
 * a deployment whose data and config dirs coincide can't mix them up.)
 */
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { JsonStore, type InviteStore, type PrincipalStore } from './stores.js';
import { emailKey, looksLikeEmail } from './google.js';
import { INVISIBLE, type AccountStore } from './accounts.js';

export interface Ticket {
  /** Opaque, random, fixed at creation: what invites and enrolled agents
   *  refer to, and the placeholder sponsor (`ticket:<id>`) until the holder
   *  has an account. */
  id: string;
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
  /** The holder's name as the ticket site knows it — what their account
   *  and the agents they sponsor are called; never the address. */
  name?: string;
  note?: string;
  /** The account the first email sign-up made (or linked) with it. */
  claimedBy?: string;
  claimedAt?: string;
  /** Agent invites ever minted for it (claimed, revoked or not): the lifetime cap counts these. */
  invitesMinted?: number;
}

export type RemovedTicket = Ticket & { removedAt: string };

export interface TicketsFile {
  tickets: Ticket[];
  /** Tickets since removed (refunds), kept so a redelivered reference makes
   *  nothing and the site can still list the invites. Bounded; oldest fall off. */
  removed?: RemovedTicket[];
}

const REMOVED_KEPT = 5000;

export function newTicketId(): string {
  return `tk_${randomBytes(6).toString('hex')}`;
}

/** Control, direction and separator characters out, length bounded: what
 *  the ticket site sends is stored and logged as is otherwise. */
export function clean(s: unknown, max: number): string {
  return typeof s === 'string' ? s.replace(INVISIBLE, '').trim().slice(0, max) : '';
}

const dedupe = (xs: string[]) => [...new Set(xs)];

/** Addresses this feature takes: printable ASCII only. A look-alike in
 *  another script (U+212A KELVIN SIGN folds to k) would match one mailbox
 *  by key and be mailed at another. */
export function usableEmail(s: string): boolean {
  return looksLikeEmail(s) && s.length <= 254 && /^[\x21-\x7e]+$/.test(s);
}

export function ticketsProblem(raw: unknown): string | null {
  const f = raw as TicketsFile;
  if (!f || typeof f !== 'object' || !Array.isArray(f.tickets)) return 'not a tickets file';
  if (f.removed !== undefined && !(Array.isArray(f.removed) && f.removed.every((t) => t && typeof t.id === 'string' && typeof t.email === 'string' && typeof t.removedAt === 'string'))) return 'bad removed';
  const strings = (v: unknown) => Array.isArray(v) && v.every((s) => typeof s === 'string' && s.length > 0);
  const keys = new Set<string>();
  const ids = new Set<string>();
  for (const t of f.tickets) {
    if (!t || typeof t.id !== 'string' || !t.id) return 'ticket without an id';
    if (ids.has(t.id)) return `two tickets with id ${t.id}`;
    ids.add(t.id);
    if (typeof t.email !== 'string' || !looksLikeEmail(t.email)) return 'bad ticket email';
    const k = emailKey(t.email);
    if (keys.has(k)) return `two tickets for ${t.email}`;
    keys.add(k);
    if (typeof t.source !== 'string' || typeof t.addedAt !== 'string') return `bad ticket for ${t.email}`;
    if (!strings(t.audiences) || !strings(t.scopes)) return `bad audiences/scopes on the ticket for ${t.email}`;
    if (t.claimedBy !== undefined && typeof t.claimedBy !== 'string') return `bad claimedBy on the ticket for ${t.email}`;
    if (t.refs !== undefined && !strings(t.refs)) return `bad refs on the ticket for ${t.email}`;
    if (t.name !== undefined && typeof t.name !== 'string') return `bad name on the ticket for ${t.email}`;
    if (t.invitesMinted !== undefined && !(Number.isInteger(t.invitesMinted) && t.invitesMinted >= 0)) return `bad invitesMinted on the ticket for ${t.email}`;
  }
  return null;
}

function validate(raw: unknown): TicketsFile | null {
  if (ticketsProblem(raw)) return null;
  const f = raw as TicketsFile;
  return { tickets: f.tickets, ...(f.removed?.length ? { removed: f.removed } : {}) };
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
    return this.all().find((t) => hasRef(t, ref));
  }
  byId(id: string): Ticket | undefined {
    return this.all().find((t) => t.id === id);
  }

  /** A refunded ticket, by address or reference — for the site's listing. */
  removedTicket(opts: { email?: string; ref?: string }): RemovedTicket | undefined {
    this.store.refresh();
    const k = opts.email ? emailKey(opts.email) : null;
    return [...(this.store.get().removed ?? [])].reverse().find((t) => (k !== null && emailKey(t.email) === k) || (opts.ref !== undefined && hasRef(t, opts.ref)));
  }

  /**
   * Add a ticket for an address; one that already holds a ticket is left as
   * it is (`created: false`) — a redelivered webhook or a repeated purchase
   * doesn't make a second one.
   */
  add(t: Omit<Ticket, 'addedAt' | 'id'>, nowMs = Date.now()): { ticket: Ticket; created: boolean } {
    if (!usableEmail(t.email)) throw new Error(`not a usable email address: ${t.email}`);
    const k = emailKey(t.email);
    let out: { ticket: Ticket; created: boolean } | undefined;
    this.store.update((f) => {
      const existing = f.tickets.find((x) => emailKey(x.email) === k);
      if (existing) {
        out = { ticket: existing, created: false };
        return f;
      }
      const ticket: Ticket = { id: newTicketId(), ...t, email: t.email.trim(), audiences: dedupe(t.audiences), scopes: dedupe(t.scopes), addedAt: new Date(nowMs).toISOString() };
      out = { ticket, created: true };
      return { ...f, tickets: [...f.tickets, ticket] };
    });
    return out!;
  }

  /** A further purchase for a mailbox that already holds a ticket: the
   *  ref is recorded (so it answers idempotently), and any grant it brings
   *  is merged in — a second purchase can only widen, never narrow. */
  addRef(email: string, ref: string, more: { audiences?: string[]; scopes?: string[]; name?: string } = {}): Ticket | undefined {
    const k = emailKey(email);
    let out: Ticket | undefined;
    this.store.update((f) => {
      const t = f.tickets.find((x) => emailKey(x.email) === k);
      if (!t) return f;
      const known = t.source === `api:${ref}` || t.refs?.includes(ref);
      const union = (a: string[], b?: string[]) => [...new Set([...a, ...(b ?? [])])];
      out = {
        ...t,
        ...(known ? {} : { refs: [...(t.refs ?? []), ref] }),
        audiences: union(t.audiences, more.audiences),
        scopes: union(t.scopes, more.scopes),
        ...(more.name && !t.name ? { name: more.name } : {}),
      };
      if (JSON.stringify(out) === JSON.stringify(t)) {
        out = t;
        return f;
      }
      return { ...f, tickets: f.tickets.map((x) => (x === t ? out! : x)) };
    });
    return out;
  }

  /** One more invite minted for the ticket. */
  countInvite(id: string): Ticket | undefined {
    let out: Ticket | undefined;
    this.store.update((f) => {
      const t = f.tickets.find((x) => x.id === id);
      if (!t) return f;
      out = { ...t, invitesMinted: (t.invitesMinted ?? 0) + 1 };
      return { ...f, tickets: f.tickets.map((x) => (x === t ? out! : x)) };
    });
    return out;
  }

  /** Was this ref's ticket removed? (A redelivery after a refund.) */
  removed(ref: string): boolean {
    return this.removedTicket({ ref }) !== undefined;
  }

  /** Remove the entitlement (the ticket is kept under `removed`). What it
   *  gave is taken back by takeBackTicket — callers run that FIRST, so a
   *  failure there leaves the ticket in place to retry. */
  remove(email: string, nowMs = Date.now()): Ticket | undefined {
    const k = emailKey(email);
    let out: Ticket | undefined;
    this.store.update((f) => {
      out = f.tickets.find((x) => emailKey(x.email) === k);
      if (!out) return f;
      const removed = [...(f.removed ?? []), { ...out, removedAt: new Date(nowMs).toISOString() }].slice(-REMOVED_KEPT);
      return { tickets: f.tickets.filter((x) => x !== out), removed };
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
  /** False for the built-in "no file" value: no ticket can be made at all. */
  configured: boolean;
  /** What a ticket carries when nothing says otherwise. */
  audiences: string[];
  scopes: string[];
  /** The most a ticket may carry, whoever asks (the ticket site, the
   *  operator): a grant outside these is refused. Defaults to the defaults. */
  allowed: { audiences: string[]; scopes: string[] };
  /** Agent invites per ticket: unclaimed at a time, and ever. */
  invites: { active: number; lifetime: number };
}

export const DEFAULT_INVITE_BUDGET = { active: 3, lifetime: 10 };
export const NO_TICKET_DEFAULTS: TicketDefaults = { configured: false, audiences: [], scopes: [], allowed: { audiences: [], scopes: [] }, invites: DEFAULT_INVITE_BUDGET };

/** Audiences of this node itself: never a ticket's. */
const BUILT_IN = new Set(['console', 'account']);
/** Scopes of this node's own authority (`id:anchor`, …): never a ticket's. */
const isHomeScope = (s: string) => s === 'id:anchor' || s.startsWith('id:');

/** Why no ticket can be made: the file is missing, or present but refused. */
export function noDefaultsMessage(configDir: string): string {
  const path = `${configDir}/ticket-defaults.json`;
  return existsSync(path)
    ? `${path} is present but refused — see the server log, fix the file (it is hot-reloaded)`
    : `no ${path} — copy config/ticket-defaults.example.json there and edit it`;
}

/** Strict like invite-policy.json: a typo refuses the file and the last good
 *  one stays, rather than silently granting nothing. Keys starting with "_" are comments. */
export function ticketDefaultsProblem(raw: unknown): string | null {
  const f = raw as Record<string, unknown>;
  if (!f || typeof f !== 'object' || Array.isArray(f)) return 'not an object';
  for (const k of Object.keys(f)) if (!k.startsWith('_') && !['audiences', 'scopes', 'allowed', 'invites'].includes(k)) return `unknown key "${k}"`;
  const isStrings = (v: unknown) => Array.isArray(v) && v.every((s) => typeof s === 'string' && s.length > 0);
  if (!isStrings(f.audiences) || !(f.audiences as string[]).length) return 'audiences must be a non-empty list of audience names';
  if (!isStrings(f.scopes)) return 'scopes must be a list of scopes';
  if ((f.audiences as string[]).some((a) => BUILT_IN.has(a))) return 'audiences: console and account are this node’s own, never a ticket’s';
  if ((f.scopes as string[]).some(isHomeScope)) return 'scopes: id:* is this node’s own authority, never a ticket’s';
  if (f.invites !== undefined) {
    const i = f.invites as Record<string, unknown>;
    if (!i || typeof i !== 'object' || Array.isArray(i)) return 'invites must be an object: { "active": 3, "lifetime": 10 }';
    for (const k of Object.keys(i)) if (!k.startsWith('_') && k !== 'active' && k !== 'lifetime') return `unknown key "invites.${k}"`;
    const whole = (v: unknown) => typeof v === 'number' && Number.isInteger(v) && v >= 0;
    if (!whole(i.active) || !whole(i.lifetime)) return 'invites.active and invites.lifetime must be whole numbers';
    if ((i.active as number) > (i.lifetime as number)) return 'invites.active can’t exceed invites.lifetime';
  }
  if (f.allowed !== undefined) {
    const a = f.allowed as Record<string, unknown>;
    if (!a || typeof a !== 'object' || Array.isArray(a)) return 'allowed must be an object: { "audiences": [...], "scopes": [...] }';
    for (const k of Object.keys(a)) if (!k.startsWith('_') && k !== 'audiences' && k !== 'scopes') return `unknown key "allowed.${k}"`;
    if (!isStrings(a.audiences)) return 'allowed.audiences must be a list of audience names';
    if (!isStrings(a.scopes)) return 'allowed.scopes must be a list of scopes';
    if ((a.audiences as string[]).some((x) => BUILT_IN.has(x))) return 'allowed.audiences: console and account are this node’s own, never a ticket’s';
    if ((a.scopes as string[]).some(isHomeScope)) return 'allowed.scopes: id:* is this node’s own authority, never a ticket’s';
    const miss = (f.audiences as string[]).find((x) => !(a.audiences as string[]).includes(x)) ?? (f.scopes as string[]).find((x) => !(a.scopes as string[]).includes(x));
    if (miss) return `the default "${miss}" is not in allowed — the defaults must be allowed too`;
  }
  return null;
}

/**
 * Whether a ticket may carry this grant — the one check behind the ticket
 * site's POST /tickets and `hn ticket add`: only audiences and scopes the
 * defaults file allows, only audiences the node knows, never its own, and
 * never nothing. `null` = fine.
 */
export function ticketGrantProblem(d: TicketDefaults, known: string[], audiences: string[], scopes: string[]): string | null {
  if (!d.configured) return 'no config/ticket-defaults.json — this node makes no tickets';
  if (!audiences.length) return 'a ticket needs at least one audience';
  for (const a of audiences) {
    if (BUILT_IN.has(a)) return `audience "${a}" is this node’s own, never a ticket’s`;
    if (!d.allowed.audiences.includes(a)) return `audience "${a}" is not one a ticket may carry (ticket-defaults.json allowed.audiences)`;
    if (!known.includes(a)) return `no audience "${a}" in audiences.json`;
  }
  for (const s of scopes) {
    if (isHomeScope(s)) return `scope "${s}" is this node’s own authority, never a ticket’s`;
    if (!d.allowed.scopes.includes(s)) return `scope "${s}" is not one a ticket may carry (ticket-defaults.json allowed.scopes)`;
  }
  return null;
}

function hasRef(t: Ticket, ref: string): boolean {
  return t.source === `api:${ref}` || Boolean(t.refs?.includes(ref));
}

/** The sponsor an agent carries until the ticket's holder has an account here. */
export function ticketPlaceholderSub(t: Pick<Ticket, 'id'>): string {
  return `ticket:${t.id}`;
}

/** The subs whose invites belong to this ticket: its placeholder, and the
 *  account that took it up. */
export function ticketSponsorSubs(t: Pick<Ticket, 'id' | 'claimedBy'>): string[] {
  return [ticketPlaceholderSub(t), ...(t.claimedBy ? [t.claimedBy] : [])];
}

export interface TicketStores {
  accounts: AccountStore;
  invites: InviteStore;
  principals: PrincipalStore;
}

/**
 * A refund: everything the ticket gave goes, the identities stay. The
 * account that took it up loses its copy of the grant (any account whose
 * copy is this ticket's, so a drifted `claimedBy` can't shelter one); the
 * ticket's unclaimed invites are revoked; agents enrolled through its
 * invites keep their identity and lose every scope and audience. Run BEFORE
 * the ticket is removed: if this throws (a held lock, a full disk), the
 * ticket stays and the refund can be retried.
 */
export function takeBackTicket(t: Pick<Ticket, 'id' | 'email' | 'claimedBy'>, s: TicketStores): { accounts: number; invites: number; agents: number } {
  const k = emailKey(t.email);
  const subs = new Set([...(t.claimedBy ? [t.claimedBy] : []), ...s.accounts.all().filter((a) => a.ticket && emailKey(a.ticket.email) === k).map((a) => a.sub)]);
  let accounts = 0;
  for (const sub of subs) {
    s.accounts.update(sub, (a) => {
      if (!a.ticket) return a;
      accounts += 1;
      const { ticket: _t, ...rest } = a;
      return rest;
    });
  }
  let invites = 0;
  for (const i of s.invites.all()) {
    if (i.ticket !== t.id || (i.uses ?? 0) >= (i.maxUses ?? 1)) continue;
    if (s.invites.revoke(i.code)) invites += 1;
  }
  let agents = 0;
  for (const p of s.principals.all()) {
    if (p.sponsorTicket !== t.id || (!p.scopes.length && p.audiences?.length === 0)) continue;
    s.principals.update(p.sub, (x) => ({ ...x, scopes: [], audiences: [], notes: `${x.notes ? `${x.notes}; ` : ''}ticket ${t.id} refunded: grant taken back` }));
    agents += 1;
  }
  return { accounts, invites, agents };
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
      const f = raw as { audiences: string[]; scopes: string[]; allowed?: { audiences: string[]; scopes: string[] }; invites?: { active: number; lifetime: number } };
      return {
        configured: true, audiences: dedupe(f.audiences), scopes: dedupe(f.scopes),
        allowed: { audiences: dedupe(f.allowed?.audiences ?? f.audiences), scopes: dedupe(f.allowed?.scopes ?? f.scopes) },
        invites: { active: f.invites?.active ?? DEFAULT_INVITE_BUDGET.active, lifetime: f.invites?.lifetime ?? DEFAULT_INVITE_BUDGET.lifetime },
      };
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
