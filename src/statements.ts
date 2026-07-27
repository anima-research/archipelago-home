/**
 * Signed-statement wire shapes for the agent legs (docs/home-node.md §4) —
 * a generalization of the shipped observer handshake
 * (`connectome-observer|v1|<host>|<timestamp>`). Challenge-less: the client
 * signs a statement binding issuer + purpose + a fresh timestamp.
 */
import type { KeyObject } from 'node:crypto';
import { signBytes } from './keys.js';

export const FRESHNESS_MS = 5 * 60_000;

export function tokenStatement(iss: string, audience: string, timestamp: string): string {
  return `archipelago-token|v1|${iss}|${audience}|${timestamp}`;
}

export function enrollStatement(iss: string, code: string, timestamp: string): string {
  return `archipelago-enroll|v1|${iss}|${code}|${timestamp}`;
}

/** POST /token body. */
export interface TokenRequest {
  /** `ed25519:<b64url raw 32B pubkey>` — must match an enrolled principal. */
  id: string;
  audience: string;
  /** ISO-8601, freshness-checked ±5 min. */
  timestamp: string;
  /** base64url sig over tokenStatement(iss, audience, timestamp). */
  proof: string;
}

/** POST /enroll body. */
export interface EnrollRequest {
  invite: string;
  id: string;
  /** Desired display name; uniqueness enforced server-side. */
  name: string;
  timestamp: string;
  /** base64url sig over enrollStatement(iss, invite, timestamp). */
  proof: string;
}

// ── Client-side helpers (agents / tests) ──

export function makeTokenRequest(privateKey: KeyObject, id: string, iss: string, audience: string): TokenRequest {
  const timestamp = new Date().toISOString();
  const proof = signBytes(privateKey, Buffer.from(tokenStatement(iss, audience, timestamp), 'utf8'));
  return { id, audience, timestamp, proof: proof.toString('base64url') };
}

export function makeEnrollRequest(
  privateKey: KeyObject,
  id: string,
  iss: string,
  invite: string,
  name: string,
): EnrollRequest {
  const timestamp = new Date().toISOString();
  const proof = signBytes(privateKey, Buffer.from(enrollStatement(iss, invite, timestamp), 'utf8'));
  return { invite, id, name, timestamp, proof: proof.toString('base64url') };
}
