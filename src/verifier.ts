/**
 * The audience-side module (docs/home-node.md §5) — everything a service
 * needs to accept aid1 tokens, importable as
 * `@animalabs/archipelago-home/verifier` (or copy this file + token.ts +
 * keys.ts). Zero dependencies beyond node:crypto.
 *
 * Contract: verify (offline) → for humans, swap for your own session
 * cookie; for agents the token IS the per-connection credential. Key your
 * state by `payload.sub`, never by connection. Echo the resolved identity
 * back to the client.
 */
export { verifyToken, JtiCache, TOKEN_PREFIX } from './token.js';
export type { Aid1Payload, PrincipalKind, VerifyOpts, VerifyOutcome } from './token.js';

export interface WellKnownIdentity {
  scheme: 'ed25519';
  domain: string;
  /** `ed25519:<b64url raw 32B>` */
  publicKey: string;
}

/**
 * Resolve the issuer public key: env/config pin wins; otherwise fetch
 * `https://<domain>/.well-known/mcpl-identity` and cache it for the process
 * lifetime. Pin fallback means a home-node outage never blocks restart of a
 * service that has the key pinned.
 */
export async function resolveIssuerKey(opts: {
  domain: string;
  pinned?: string;
  fetchImpl?: typeof fetch;
}): Promise<string> {
  if (opts.pinned) return opts.pinned;
  const f = opts.fetchImpl ?? fetch;
  const res = await f(`https://${opts.domain}/.well-known/mcpl-identity`);
  if (!res.ok) throw new Error(`well-known fetch failed: ${res.status}`);
  const wk = (await res.json()) as WellKnownIdentity;
  if (wk?.scheme !== 'ed25519' || typeof wk.publicKey !== 'string' || !wk.publicKey.startsWith('ed25519:')) {
    throw new Error('malformed well-known identity document');
  }
  return wk.publicKey;
}
