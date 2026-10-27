/**
 * The invite policy — what a sponsor's console invite carries — as part of a
 * deployment, not of the code: `config/invites.json`, hot-reloaded like
 * audiences.json and roles.json. A home with other services writes its own;
 * Anima's is config/invites.example.json.
 *
 *   {
 *     "console":         { "requiredScopes": ["worlds:join"] },
 *     "primaryAudience": "eidoverse",
 *     "scopes": {
 *       "worlds:join":  ["delegable", "resident"],
 *       "music:scribe": ["delegable", "anchorGrantable", "resident"],
 *       "docs:use":     ["delegable", "baseline", "resident"],
 *       "board:write":  ["resident"]
 *     },
 *     "audiences": [
 *       { "audience": "eidoverse",  "always": true },
 *       { "audience": "music",      "when": ["music:*"] },
 *       { "audience": "body",       "anchored": true },
 *       { "audience": "clawblox-*", "when": ["clawblox:play"] }
 *     ]
 *   }
 *
 * Scope roles (a scope may have several; a scope with none is never granted
 * through the console):
 *   delegable        a sponsor may pass it on — only if they hold it (∩)
 *   anchorGrantable  an `id:anchor` holder may grant it outright
 *   baseline         every invite carries it, whoever mints it
 *   resident         an anchored invite carries it, whatever the sponsor holds
 *
 * Audience rules, in order — an invite gets a rule's audience when the rule
 * is `always`, when the invite is anchored and the rule is `anchored`, or
 * when any of the invite's scopes matches a `when` pattern (exact, or
 * `prefix:*`). An audience ending in `*` stands for every REGISTERED
 * audience (audiences.json) it matches, e.g. one per world. The primary
 * audience leads the list: enrollment's first token is for audiences[0].
 *
 * The console gate: `console.requiredScopes` are what a person must hold to
 * open the console and mint at all. With no invites.json at all (or one
 * that has never parsed), the console is off and says so; nothing else on
 * the node depends on this file. Keys starting with "_" are comments.
 */
import { JsonStore } from './stores.js';

export const SCOPE_ROLES = ['delegable', 'anchorGrantable', 'baseline', 'resident'] as const;
export type ScopeRole = (typeof SCOPE_ROLES)[number];

export interface AudienceRule {
  audience: string;
  always?: boolean;
  anchored?: boolean;
  when?: string[];
}

export interface InvitePolicy {
  /** False only for the built-in "no file" value: the console is off. */
  configured: boolean;
  console?: { requiredScopes?: string[] };
  primaryAudience?: string;
  scopes: Record<string, ScopeRole[]>;
  audiences: AudienceRule[];
}

export const NO_POLICY: InvitePolicy = { configured: false, scopes: {}, audiences: [] };

/** The file's problem, or null. Strict on purpose: a typo'd role or key
 *  refuses the whole file (the previous good policy stays in force) rather
 *  than silently granting less — or more — than meant. */
export function invitePolicyProblem(raw: unknown): string | null {
  const isStrings = (v: unknown) => Array.isArray(v) && v.every((s) => typeof s === 'string' && s.length > 0);
  const f = raw as Record<string, unknown>;
  if (!f || typeof f !== 'object' || Array.isArray(f)) return 'not an object';
  for (const k of Object.keys(f)) {
    if (!k.startsWith('_') && !['console', 'primaryAudience', 'scopes', 'audiences'].includes(k)) return `unknown key "${k}"`;
  }
  if (f.console !== undefined) {
    const c = f.console as Record<string, unknown>;
    if (!c || typeof c !== 'object') return 'console must be an object';
    for (const k of Object.keys(c)) if (!k.startsWith('_') && k !== 'requiredScopes') return `unknown key "console.${k}"`;
    if (c.requiredScopes !== undefined && !isStrings(c.requiredScopes)) return 'console.requiredScopes must be a list of scopes';
  }
  if (f.primaryAudience !== undefined && (typeof f.primaryAudience !== 'string' || !f.primaryAudience)) {
    return 'primaryAudience must be an audience name';
  }
  const scopes = f.scopes as Record<string, unknown>;
  if (!scopes || typeof scopes !== 'object' || Array.isArray(scopes)) return 'scopes must be an object';
  for (const [s, roles] of Object.entries(scopes)) {
    if (s.startsWith('_')) continue;
    if (!Array.isArray(roles)) return `scopes["${s}"] must be a list of roles`;
    for (const r of roles) if (!SCOPE_ROLES.includes(r as ScopeRole)) return `scopes["${s}"]: unknown role "${String(r)}" (${SCOPE_ROLES.join(', ')})`;
  }
  if (!Array.isArray(f.audiences)) return 'audiences must be a list of rules';
  for (const [i, rule] of (f.audiences as unknown[]).entries()) {
    const r = rule as Record<string, unknown>;
    if (!r || typeof r !== 'object') return `audiences[${i}] must be an object`;
    for (const k of Object.keys(r)) {
      if (!k.startsWith('_') && !['audience', 'always', 'anchored', 'when'].includes(k)) return `audiences[${i}]: unknown key "${k}"`;
    }
    if (typeof r.audience !== 'string' || !r.audience) return `audiences[${i}].audience must be a name`;
    if (r.always !== undefined && typeof r.always !== 'boolean') return `audiences[${i}].always must be true/false`;
    if (r.anchored !== undefined && typeof r.anchored !== 'boolean') return `audiences[${i}].anchored must be true/false`;
    if (r.when !== undefined && !isStrings(r.when)) return `audiences[${i}].when must be a list of scope patterns`;
    if (!r.always && !r.anchored && !r.when) return `audiences[${i}] ("${r.audience}") never applies — give it always, anchored or when`;
  }
  return null;
}

function validate(raw: unknown): InvitePolicy | null {
  const bad = invitePolicyProblem(raw);
  if (bad) {
    console.error(`[hn] invites: ${bad}`);
    return null;
  }
  const f = raw as Omit<InvitePolicy, 'configured'>;
  const scopes = Object.fromEntries(Object.entries(f.scopes).filter(([s]) => !s.startsWith('_')));
  return { ...f, scopes, configured: true };
}

export function invitePolicyStore(path: string): JsonStore<InvitePolicy> {
  return new JsonStore<InvitePolicy>(path, validate, NO_POLICY, 'invites');
}

// ── the rules, pure ──

export function scopesWithRole(p: InvitePolicy, role: ScopeRole): string[] {
  return Object.entries(p.scopes).filter(([, roles]) => roles.includes(role)).map(([s]) => s);
}

/** What a person must hold to use the console; null = no console here. */
export function consoleRequiredScopes(p: InvitePolicy): string[] | null {
  return p.configured ? (p.console?.requiredScopes ?? []) : null;
}

function matches(scope: string, pattern: string): boolean {
  return pattern.endsWith(':*') ? scope.startsWith(pattern.slice(0, -1)) : scope === pattern;
}

function globMatches(name: string, glob: string): boolean {
  return glob.endsWith('*') ? name.startsWith(glob.slice(0, -1)) : name === glob;
}

/** The audiences an invite carrying `scopes` lets its principal ask tokens
 *  for. `known` = the registered audiences, for `*` rules. */
export function audiencesFor(p: InvitePolicy, scopes: string[], anchored: boolean, known: string[] = []): string[] {
  const out: string[] = [];
  const add = (a: string) => {
    if (!out.includes(a)) out.push(a);
  };
  for (const r of p.audiences) {
    const applies = r.always || (anchored && r.anchored) || (r.when ?? []).some((pat) => scopes.some((s) => matches(s, pat)));
    if (!applies) continue;
    if (r.audience.endsWith('*')) known.filter((a) => globMatches(a, r.audience)).sort().forEach(add);
    else add(r.audience);
  }
  const primary = p.primaryAudience;
  return primary && out.includes(primary) ? [primary, ...out.filter((a) => a !== primary)] : out;
}
