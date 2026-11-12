/**
 * Sign-in sessions: after someone signs in here by any method, a cookie on
 * this node lets them "continue as" that account the next time a service
 * sends them to /login, and opens their own account page straight away, so
 * they don't sign in twice. A session is not a token: it never leaves the
 * node, and every use still goes through the same checks a sign-in does
 * (the account must exist and not be disabled; the audience's rules apply).
 *
 * Only a hash of the cookie is stored (data/sessions.json, 0600). Sessions
 * last SESSION_DAYS; expired ones are dropped whenever the file is written.
 */
import { createHash, randomBytes } from 'node:crypto';
import { JsonStore } from './stores.js';

export const SESSION_COOKIE = 'hn_session';
export const SESSION_DAYS = 30;

export interface Session {
  /** sha256 of the cookie value, base64url. */
  id: string;
  sub: string;
  /** How they signed in to start it (email, google, passkey, …). */
  by: string;
  createdAt: string;
  expiresAt: string;
}

const hash = (v: string): string => createHash('sha256').update(v).digest('base64url');

export class SessionStore {
  private readonly store: JsonStore<{ sessions: Session[] }>;

  constructor(path: string) {
    this.store = new JsonStore<{ sessions: Session[] }>(
      path,
      (raw) => {
        const r = raw as { sessions?: unknown } | null;
        return r && Array.isArray(r.sessions) ? (r as { sessions: Session[] }) : null;
      },
      { sessions: [] },
      'sessions',
      0o600,
    );
  }

  /** A new session for this account; returns the cookie value (only its hash is kept). */
  create(sub: string, by: string, nowMs = Date.now()): { value: string; maxAgeS: number } {
    const value = randomBytes(32).toString('base64url');
    const now = new Date(nowMs);
    const exp = new Date(nowMs + SESSION_DAYS * 86_400_000);
    this.store.update((f) => ({
      sessions: [...f.sessions.filter((s) => Date.parse(s.expiresAt) > nowMs), { id: hash(value), sub, by, createdAt: now.toISOString(), expiresAt: exp.toISOString() }],
    }));
    return { value, maxAgeS: SESSION_DAYS * 86_400 };
  }

  /** The live session behind a cookie value, if any. */
  find(value: string, nowMs = Date.now()): Session | undefined {
    if (!value) return undefined;
    const id = hash(value);
    return this.store.get().sessions.find((s) => s.id === id && Date.parse(s.expiresAt) > nowMs);
  }

  /** Ends the session behind a cookie value. */
  end(value: string): void {
    if (!value) return;
    const id = hash(value);
    this.store.update((f) => (f.sessions.some((s) => s.id === id) ? { sessions: f.sessions.filter((s) => s.id !== id) } : f));
  }

  all(): Session[] {
    return this.store.get().sessions;
  }
}
