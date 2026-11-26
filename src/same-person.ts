/**
 * One person, one account: what this node does about someone who signs in
 * with both Discord and Google.
 *
 * 1. The same address on both sides. Discord vouches for an account's
 *    address (`verified`: they followed a mailed link); Google vouches for a
 *    Gmail or Workspace address (google.ts). When both vouch for the same
 *    mailbox it is the same person, and the second provider to show up
 *    becomes another way into the account the first one has — not a second
 *    account (human.ts). To recognise a Google account that arrives later,
 *    the node remembers which address each Discord account last vouched
 *    for: a hash of it, in data/discord-addresses.json, not the address.
 *    (A plain hash: it keeps addresses out of sight, and whoever can read
 *    the file can still test a guess against it.)
 *
 *    Not for everyone: someone holding one of the node's own powers
 *    (hn:admin, id:anchor), or under operator restrictions, is never joined
 *    this way — for them a second provider would be a second way in that
 *    nobody chose. They link by hand on the account page.
 *
 * 2. Different addresses. There is nothing to match on, so the node asks: a
 *    Google account it has never seen gets a page first ("I've signed in
 *    here with Discord" / "I'm new here") and no account until they answer
 *    (human.ts, pages.ts firstGooglePage).
 *
 * 3. Two accounts already. `hn user merge <from> <into>` folds one into the
 *    other (mergeAccounts); `hn user dupes` lists the pairs the node can
 *    see for itself (sameAddress).
 */
import { createHash } from 'node:crypto';
import { JsonStore } from './stores.js';
import { emailKey } from './google.js';
import type { HumanAccount } from './accounts.js';

// ── which address each Discord account last vouched for ──

export interface DiscordAddresses {
  /** Discord id → sha256 of the address as mail is delivered (emailKey), and when it was first seen. */
  addresses: Record<string, { hash: string; at: string }>;
}

export const addressHash = (email: string): string => createHash('sha256').update(emailKey(email)).digest('hex');

export class DiscordAddressStore {
  private readonly store: JsonStore<DiscordAddresses>;

  constructor(path: string) {
    this.store = new JsonStore<DiscordAddresses>(
      path,
      (raw) => {
        const a = (raw as DiscordAddresses | null)?.addresses;
        if (!a || typeof a !== 'object' || Array.isArray(a)) return null;
        return Object.values(a).every((v) => typeof v?.hash === 'string' && typeof v.at === 'string') ? (raw as DiscordAddresses) : null;
      },
      { addresses: {} },
      'discord addresses',
      0o600,
    );
  }

  /** What Discord says at this sign-in: the address it vouches for, or null
   *  (none, or not verified) — which forgets the one it vouched for before. */
  record(id: string, email: string | null, nowMs = Date.now()): void {
    const hash = email ? addressHash(email) : null;
    if ((this.store.get().addresses[id]?.hash ?? null) === hash) return;
    this.store.update((f) => {
      const { [id]: _was, ...rest } = f.addresses;
      return { addresses: hash ? { ...rest, [id]: { hash, at: new Date(nowMs).toISOString() } } : rest };
    });
  }

  /** The Discord accounts that last vouched for this address. */
  idsFor(email: string): string[] {
    const h = addressHash(email);
    return Object.entries(this.store.get().addresses).filter(([, v]) => v.hash === h).map(([id]) => id);
  }

  all(): DiscordAddresses['addresses'] {
    return this.store.get().addresses;
  }
}

/** A Discord account and a Google-linked account that share a vouched-for
 *  address without being one account: two accounts for one person. */
export function sameAddress(accounts: HumanAccount[], addresses: DiscordAddresses['addresses']): Array<{ discordId: string; google: HumanAccount }> {
  const out: Array<{ discordId: string; google: HumanAccount }> = [];
  for (const [discordId, { hash }] of Object.entries(addresses)) {
    for (const a of accounts) {
      if (a.google?.sub && a.google.verified && a.discord?.id !== discordId && addressHash(a.google.email) === hash) out.push({ discordId, google: a });
    }
  }
  return out;
}

// ── folding one account into another ──

export interface Merged {
  /** The account that stays, holding what both held. */
  next: HumanAccount;
  /** What `from` had that couldn't come along, in words for the operator. */
  left: string[];
}

/**
 * `from` folded into `into`: `into` keeps its sub and its name, and takes
 * `from`'s ways in and whatever it was granted. A string instead = why not
 * (both hold something an account has one of). Restrictions add up — a
 * merge never frees anyone from one.
 */
export function mergeAccounts(from: HumanAccount, into: HumanAccount, day: string): Merged | string {
  if (from.sub === into.sub) return 'that is one account';
  if (from.disabled || into.disabled) return 'one of them is disabled — a merge would let them back in; enable it first if that is meant';
  if (from.discord && into.discord && from.discord.id !== into.discord.id) return 'both sign in with a Discord account, and an account takes one';
  if (from.google?.sub && into.google?.sub) return 'both sign in with a Google account, and an account takes one (hn user set <one of them> --google none)';
  if (from.email && into.email) return 'both sign in with an email address, and an account takes one';

  const next = structuredClone(into);
  const left: string[] = [];
  if (from.discord && !next.discord) next.discord = from.discord;
  if (from.google?.sub) {
    if (next.google) left.push(`${into.sub}'s unused Google invitation (${next.google.email})`);
    next.google = from.google;
  } else if (from.google) {
    if (next.google) left.push(`its unused Google invitation (${from.google.email})`);
    else next.google = from.google;
  }
  if (from.email) next.email = from.email;
  if (from.ticket) {
    if (next.ticket) left.push(`its ticket (${from.ticket.source}): ${into.sub} holds one already`);
    else next.ticket = from.ticket;
  }
  if (from.username || from.password) {
    if (next.username || next.password) left.push(`its username and password${from.username ? ` (${from.username})` : ''}: ${into.sub} has its own`);
    else {
      if (from.username) next.username = from.username;
      if (from.password) next.password = from.password;
      if (from.totp) next.totp = from.totp;
      if (from.recovery) next.recovery = from.recovery;
    }
  }
  if (from.passkeys?.length) {
    // a passkey answers to the account it was made for (webauthnUserId): it moves only where there is none yet
    if (next.passkeys?.length) left.push(`its ${from.passkeys.length} passkey(s): they were made for the other account, and are added again from the account page`);
    else {
      next.passkeys = from.passkeys;
      if (from.webauthnUserId) next.webauthnUserId = from.webauthnUserId;
    }
  }
  if (from.setup) left.push('its unused setup link');
  const union = (a?: string[], b?: string[]) => [...new Set([...(a ?? []), ...(b ?? [])])];
  if (from.codes?.length) next.codes = [...(next.codes ?? []), ...from.codes.filter((c) => !next.codes?.some((x) => x.id === c.id))];
  for (const k of ['scopes', 'ignoreRoles', 'withhold'] as const) {
    const u = union(next[k], from[k]);
    if (u.length) next[k] = u;
  }
  if (from.claims) next.claims = { ...from.claims, ...next.claims };
  // The Discord snapshot was taken under one side's set-aside roles: with any set aside now, only a fresh check counts.
  if (next.ignoreRoles?.length && next.discord) next.discord = { id: next.discord.id, ...(next.discord.name ? { name: next.discord.name } : {}) };
  next.was = union(next.was, [from.sub, ...(from.was ?? [])]);
  next.notes = `${next.notes ? `${next.notes}; ` : ''}merged ${from.sub} ${day}`;
  return { next, left };
}
