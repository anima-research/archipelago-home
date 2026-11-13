/**
 * `hn` — the operator CLI (docs/home-node.md §3). Local admin surface v0;
 * runs on the box against the same data/config dirs as the server.
 *
 *   hn serve
 *   hn fingerprint
 *   hn mint   --name ferro --aud eidoverse --scopes worlds:join --ttl 72h [--kind agent] [--tier sonnet-event]
 *   hn invite --scopes worlds:join [--label x] [--max-uses 1] [--expires 72h] [--aud eidoverse] [--ttl 72h]
 *   hn ls [--json]
 *   hn revoke <sub>            hn revoke-invite <code>
 *
 *   hn user add <username> [--scopes a,b] [--name "Display"] [--tier x]   → one-time setup link
 *   hn user add <username> --google alice@gmail.com [--scopes a,b] …     → no link: they Continue with Google
 *   hn user ls [--json]
 *   hn user reset <username> [--clear-2fa] [--clear-passkeys]             → new setup link
 *   hn user set <username> [--scopes a,b] [--name "Display"] [--tier x] [--google <email> | --google none]
 *   hn user disable <username>     hn user enable <username>
 *   hn user restrict <username | sub | discord-id> [--ignore-roles <role id>,…] [--withhold a,b] [--clear]
 *                                  roles that don't count for this person / scopes they never hold
 *
 *   hn code add --aud curation [--scopes x,y] [--label "…"] [--max-uses 50] [--expires 14d]  → the code (shown once)
 *   hn code ls                      who redeemed what
 *   hn code close <id>              no new redemptions (what it gave stays)
 *   hn code revoke <id>             and take back what it gave, from everyone
 */
import { join } from 'node:path';
import { statSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { loadOrCreateIssuerKey } from './keys.js';
import { mintToken, parseTtl, type Aid1Payload, type PrincipalKind } from './token.js';
import { audiencesStore, InviteStore, MintLog, PrincipalStore, type Principal } from './stores.js';
import { CodeStore } from './codes.js';
import { configFromEnv, HomeNode, type ServerConfig } from './server.js';
import { AccountStore, displayName, newSetupCode, normalizeUsername, usernameProblem, type HumanAccount } from './accounts.js';
import { emailKey, looksLikeEmail } from './google.js';

function flags(args: string[]): { flag: Map<string, string>; pos: string[] } {
  const flag = new Map<string, string>();
  const pos: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a.startsWith('--')) {
      const next = args[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        flag.set(a.slice(2), next);
        i++;
      } else flag.set(a.slice(2), 'true');
    } else pos.push(a);
  }
  return { flag, pos };
}

function die(msg: string): never {
  console.error(`hn: ${msg}`);
  process.exit(1);
}

function main(): void {
  const [cmd, ...rest] = process.argv.slice(2);
  const cfg = configFromEnv();
  const { flag, pos } = flags(rest);

  if (cmd === 'serve') {
    new HomeNode(cfg).start();
    return;
  }

  const issuer = loadOrCreateIssuerKey(join(cfg.dataDir, 'issuer-key.pem'));

  if (cmd === 'fingerprint' || cmd === undefined) {
    console.log(issuer.id);
    return;
  }

  const principals = new PrincipalStore(join(cfg.dataDir, 'principals.json'));
  const invites = new InviteStore(join(cfg.dataDir, 'invites.json'));
  const mintLog = new MintLog(join(cfg.dataDir, 'minted.jsonl'));

  switch (cmd) {
    case 'user':
      return userCmd(cfg, principals, pos, flag);
    case 'code':
      return codeCmd(cfg, pos, flag);

    case 'mint': {
      const name = flag.get('name') ?? die('--name required');
      const aud = flag.get('aud') ?? die('--aud required');
      const ttl = flag.get('ttl') ?? '72h';
      const kind = (flag.get('kind') ?? 'agent') as PrincipalKind;
      let p = principals.all().find((x) => x.name.toLowerCase() === name.toLowerCase());
      if (!p && new AccountStore(join(cfg.dataDir, 'accounts.json')).nameTaken(name)) {
        die(`"${name}" is a person's username or display name here — pick another name`);
      }
      if (p) {
        if (!principals.isLive(p)) die(`principal ${p.sub} is revoked/expired — un-revoke by editing principals.json`);
        console.error(`[hn] minting for existing principal ${p.sub}`);
      } else {
        const scopes = flag.get('scopes')?.split(',').map((s) => s.trim()).filter(Boolean) ?? die('--scopes required for a new principal');
        const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
        p = {
          sub: flag.get('sub') ?? `${kind}:${slug}@guest`,
          name,
          kind,
          key: null,
          scopes,
          ...(flag.get('tier') ? { claims: { tier: flag.get('tier') } } : {}),
          tokenTtl: ttl,
          notes: `manual mint ${new Date().toISOString().slice(0, 10)}`,
        } satisfies Principal;
        principals.add(p);
        console.error(`[hn] new principal ${p.sub}`);
      }
      const nowMs = Date.now();
      const payload: Aid1Payload = {
        v: 1,
        iss: cfg.iss,
        sub: p.sub,
        kind: p.kind,
        name: p.name,
        aud,
        scopes: p.scopes,
        ...(p.claims ? { claims: p.claims } : {}),
        iat: Math.floor(nowMs / 1000),
        exp: Math.floor((nowMs + parseTtl(ttl)) / 1000),
      };
      const token = mintToken(issuer.privateKey, payload);
      mintLog.append({ at: new Date(nowMs).toISOString(), sub: p.sub, aud, scopes: p.scopes, exp: payload.exp, by: 'cli' });
      console.error(`[hn] token for ${p.sub} → ${aud}, expires ${new Date(payload.exp * 1000).toISOString()}`);
      console.log(token);
      return;
    }

    case 'invite': {
      const scopes = flag.get('scopes')?.split(',').map((s) => s.trim()).filter(Boolean) ?? die('--scopes required');
      const expires = flag.get('expires');
      const inv = invites.mint({
        scopes,
        ...(flag.get('domain') ? { domain: flag.get('domain') } : {}),
        ...(flag.get('label') ? { label: flag.get('label') } : {}),
        ...(flag.get('max-uses') ? { maxUses: Number(flag.get('max-uses')) } : {}),
        ...(flag.get('aud') ? { audiences: flag.get('aud')!.split(',') } : {}),
        ...(flag.get('ttl') ? { tokenTtl: flag.get('ttl') } : {}),
        ...(expires
          ? { expiresAt: /^\d+[mhd]$/.test(expires) ? new Date(Date.now() + parseTtl(expires)).toISOString() : expires }
          : {}),
      });
      console.error(`[hn] invite minted (scopes: ${scopes.join(' ')})`);
      console.log(inv.code);
      return;
    }

    case 'ls': {
      if (flag.has('json')) {
        console.log(JSON.stringify({ principals: principals.all(), invites: invites.all() }, null, 2));
        return;
      }
      console.log(`issuer  ${issuer.id}`);
      console.log(`\nprincipals (${principals.all().length}):`);
      for (const p of principals.all()) {
        const dead = !principals.isLive(p) ? '  [REVOKED/EXPIRED]' : '';
        console.log(`  ${p.sub}  "${p.name}"  ${p.key ? p.key.slice(0, 20) + '…' : 'no-key'}  [${p.scopes.join(' ')}]${dead}`);
      }
      console.log(`\ninvites (${invites.all().length}):`);
      for (const i of invites.all()) {
        console.log(`  ${i.code}  ${i.label ?? ''}  [${i.scopes.join(' ')}]  uses ${i.uses ?? 0}${i.maxUses !== undefined ? `/${i.maxUses}` : ''}${i.expiresAt ? `  until ${i.expiresAt}` : ''}`);
      }
      return;
    }

    case 'revoke': {
      const sub = pos[0] ?? die('usage: hn revoke <sub>');
      if (!principals.revoke(sub)) die(`no principal ${sub}`);
      console.error(`[hn] revoked ${sub} — issuance stopped; outstanding tokens live out their exp`);
      return;
    }

    case 'revoke-invite': {
      const code = pos[0] ?? die('usage: hn revoke-invite <code>');
      if (!invites.revoke(code)) die(`no invite ${code}`);
      console.error(`[hn] invite ${code} revoked`);
      return;
    }

    default:
      die(`unknown command "${cmd}" — serve | fingerprint | mint | invite | ls | revoke | revoke-invite | user`);
  }
}

function userInfoName(uid: number): string {
  try {
    return execFileSync('id', ['-nu', String(uid)], { encoding: 'utf8' }).trim() || String(uid);
  } catch {
    return `#${uid}`;
  }
}

/** `hn user …` — human accounts (username / password / 2FA / passkeys). */
function userCmd(cfg: ServerConfig, principals: PrincipalStore, pos: string[], flag: Map<string, string>): void {
  // accounts.json is 0600: written by root, the service user could no longer
  // read it and every non-Discord sign-in would fail.
  try {
    if (process.getuid?.() === 0 && statSync(cfg.dataDir).uid !== 0) {
      die(`run as the service user, not root (e.g. sudo -u ${userInfoName(statSync(cfg.dataDir).uid)} …) — accounts.json is 0600`);
    }
  } catch {
    /* data dir missing: first run, nothing to protect */
  }
  const accounts = new AccountStore(join(cfg.dataDir, 'accounts.json'));
  const [sub, rawName] = pos;
  const scopesFlag = flag.get('scopes')?.split(',').map((s) => s.trim()).filter(Boolean);
  const setupLink = (code: string) => `${cfg.publicUrl}/account/setup#code=${code}`;
  const find = (): HumanAccount => {
    if (!rawName) die(`usage: hn user ${sub} <username | sub>`);
    return accounts.byUsername(rawName) ?? accounts.bySub(rawName) ?? die(`no account "${rawName}"`);
  };
  const describe = (a: HumanAccount) =>
    `  ${a.username ?? '—'}  ${a.sub}  "${displayName(a)}"` +
    `  pw:${a.password ? 'y' : 'n'} 2fa:${a.totp ? 'y' : 'n'} passkeys:${a.passkeys?.length ?? 0}` +
    `${a.discord ? `  discord:${a.discord.id}` : ''}${a.google ? `  google:${a.google.email}${a.google.sub ? '' : '(invited)'}` : ''}` +
    `${a.scopes?.length ? `  [${a.scopes.join(' ')}]` : ''}` +
    `${a.ignoreRoles?.length ? `  ignore-roles:${a.ignoreRoles.join(',')}` : ''}${a.withhold?.length ? `  withhold:${a.withhold.join(',')}` : ''}` +
    `${a.setup ? `  setup-link-until:${a.setup.exp.slice(0, 16)}` : ''}${a.disabled ? '  [DISABLED]' : ''}`;

  /** --google <email>: an invite by address, checked against everyone else's. */
  const googleFlag = (forSub?: string): { email: string } | null | undefined => {
    const v = flag.get('google');
    if (v === undefined) return undefined;
    if (v === 'none') return null;
    if (!looksLikeEmail(v)) die(`--google wants an email address (or "none"), got "${v}"`);
    const k = emailKey(v);
    const clash = accounts.all().find((x) => x.sub !== forSub && x.google && emailKey(x.google.email) === k);
    if (clash) die(`${v} is already on ${clash.sub}${clash.google?.sub ? ' (linked)' : ' (invited)'}`);
    return { email: v.trim() };
  };

  switch (sub) {
    case 'add': {
      const username = normalizeUsername(rawName ?? die('usage: hn user add <username> [--scopes a,b] [--name "Display"]'));
      const bad = usernameProblem(username, accounts, (n) => principals.nameTaken(n));
      if (bad) die(bad);
      const google = googleFlag();
      const { code, setup } = newSetupCode();
      const tier = flag.get('tier');
      accounts.add({
        sub: `human:local:${username}`,
        username,
        ...(flag.get('name') ? { name: flag.get('name')!.slice(0, 32) } : {}),
        ...(scopesFlag ? { scopes: scopesFlag } : {}),
        ...(tier ? { claims: { tier } } : {}),
        // Invited by Google address: that is their way in, no setup link.
        ...(google ? { google } : { setup }),
        createdAt: new Date().toISOString(),
        notes: `hn user add ${new Date().toISOString().slice(0, 10)}`,
      });
      console.error(`[hn] account human:local:${username} created [${(scopesFlag ?? []).join(' ') || 'no scopes yet — hn user set --scopes'}]`);
      if (google) {
        console.error(`[hn] they sign in with "Continue with Google" as ${google.email} (the first sign-in links it). For a password too: hn user reset ${username}`);
        return;
      }
      console.error(`[hn] send them this one-time link (valid 72h) to set a password:`);
      console.log(setupLink(code));
      return;
    }
    case 'ls': {
      if (flag.has('json')) {
        // credentials redacted — this is for reading, not backup
        const redacted = accounts.all().map(({ password, totp, recovery, setup, passkeys, ...a }) => ({
          ...a, password: Boolean(password), totp: Boolean(totp), recoveryLeft: recovery?.length ?? 0,
          setupUntil: setup?.exp ?? null, passkeys: (passkeys ?? []).map((p) => ({ name: p.name, createdAt: p.createdAt, lastUsedAt: p.lastUsedAt })),
        }));
        console.log(JSON.stringify(redacted, null, 2));
        return;
      }
      console.log(`accounts (${accounts.all().length}):`);
      for (const a of accounts.all()) console.log(describe(a));
      return;
    }
    case 'reset': {
      const a = find();
      const { code, setup } = newSetupCode();
      accounts.update(a.sub, (x) => {
        const next: HumanAccount = { ...x, setup };
        if (flag.has('clear-2fa')) {
          delete next.totp;
          delete next.recovery;
        }
        if (flag.has('clear-passkeys')) delete next.passkeys;
        return next;
      });
      console.error(`[hn] setup link for ${a.sub}${flag.has('clear-2fa') ? ' (2FA cleared)' : a.totp ? ' (2FA still on — they will need a code or recovery code)' : ''}${flag.has('clear-passkeys') ? ' (passkeys cleared)' : ''} — valid 72h; the current password keeps working until they use it:`);
      console.log(setupLink(code));
      return;
    }
    case 'set': {
      const a = find();
      const tier = flag.get('tier');
      const newName = flag.get('name');
      if (newName) {
        const n = newName.trim().toLowerCase();
        const clash = accounts.all().some((x) => x.sub !== a.sub && (x.username === n || x.name?.toLowerCase() === n));
        if (clash || principals.nameTaken(n)) die(`the name "${newName}" is already in use here`);
      }
      const google = googleFlag(a.sub);
      if (google !== undefined && a.google?.sub) console.error(`[hn] note: replacing the linked Google account (${a.google.email}) on ${a.sub}`);
      const next = accounts.update(a.sub, (x) => {
        const n: HumanAccount = {
          ...x,
          ...(scopesFlag ? { scopes: scopesFlag } : {}),
          ...(flag.get('name') ? { name: flag.get('name')!.slice(0, 32) } : {}),
          ...(tier ? { claims: { ...x.claims, tier } } : {}),
          ...(google ? { google } : {}),
        };
        if (google === null) delete n.google;
        return n;
      })!;
      console.error(`[hn] updated:`);
      console.log(describe(next));
      return;
    }
    case 'restrict': {
      // A Discord person with no row yet gets one (their sub stays human:discord:<id>).
      let a = rawName ? (accounts.byUsername(rawName) ?? accounts.bySub(rawName) ?? accounts.byDiscord(rawName.replace(/^human:discord:/, ''))) : undefined;
      if (!a && rawName && /^(human:discord:)?\d{15,22}$/.test(rawName)) {
        const id = rawName.replace(/^human:discord:/, '');
        a = accounts.add({ sub: `human:discord:${id}`, discord: { id }, createdAt: new Date().toISOString(), notes: `hn user restrict ${new Date().toISOString().slice(0, 10)}` });
        console.error(`[hn] made a row for ${a.sub} (their name fills in at their next Discord sign-in)`);
      }
      if (!a) die('usage: hn user restrict <username | sub | discord-id> [--ignore-roles <role id>,…] [--withhold a,b] [--clear]');
      const ign = flag.get('ignore-roles')?.split(',').map((s) => s.trim()).filter(Boolean);
      const wh = flag.get('withhold')?.split(',').map((s) => s.trim()).filter(Boolean);
      if (ign?.some((r) => !/^\d{15,22}$/.test(r))) die('--ignore-roles wants Discord role ids (see config/roles.json)');
      const next = accounts.update(a.sub, (x) => {
        const n: HumanAccount = { ...x, ...(ign ? { ignoreRoles: ign } : {}), ...(wh ? { withhold: wh } : {}) };
        // the last Discord check's grant predates the restriction: drop it, so only a fresh check counts
        if (ign && n.discord) n.discord = { id: n.discord.id, ...(n.discord.name ? { name: n.discord.name } : {}) };
        if (flag.has('clear')) {
          delete n.ignoreRoles;
          delete n.withhold;
        }
        return n;
      }) ?? a;
      console.error(`[hn] restricted (from their next sign-in; tokens out now live out their minutes):`);
      console.log(describe(next));
      return;
    }
    case 'disable':
    case 'enable': {
      const a = find();
      accounts.update(a.sub, (x) => ({ ...x, disabled: sub === 'disable' }));
      console.error(`[hn] ${a.sub} ${sub}d${sub === 'disable' ? ' — no new logins by any method (Discord included); outstanding tokens live out their exp' : ''}`);
      return;
    }
    default:
      die('usage: hn user add | ls | reset | set | restrict | disable | enable');
  }
}

/** `hn code …` — access codes that grant audiences to people (codes.ts). */
function codeCmd(cfg: ServerConfig, pos: string[], flag: Map<string, string>): void {
  try {
    if (process.getuid?.() === 0 && statSync(cfg.dataDir).uid !== 0) {
      die(`run as the service user, not root (e.g. sudo -u ${userInfoName(statSync(cfg.dataDir).uid)} …) — codes.json is 0600`);
    }
  } catch {
    /* data dir missing: first run */
  }
  const codes = new CodeStore(join(cfg.dataDir, 'codes.json'));
  const [sub, id] = pos;
  const list = (v?: string) => v?.split(',').map((x) => x.trim()).filter(Boolean) ?? [];
  switch (sub) {
    case 'add': {
      const audiences = list(flag.get('aud'));
      if (!audiences.length) die('usage: hn code add --aud a[,b] [--scopes x,y] [--label "…"] [--max-uses N] [--expires 14d]');
      const known = audiencesStore(join(cfg.configDir, 'audiences.json')).get();
      for (const a of audiences) if (!known[a]) die(`no audience "${a}" in ${join(cfg.configDir, 'audiences.json')}`);
      // what each audience requires comes along, so the code actually opens it
      const scopes = [...new Set([...audiences.flatMap((a) => known[a]!.requiredScopes ?? []), ...list(flag.get('scopes'))])];
      const maxUses = flag.has('max-uses') ? Number(flag.get('max-uses')) : undefined;
      if (maxUses !== undefined && !(Number.isInteger(maxUses) && maxUses > 0)) die('--max-uses wants a positive whole number');
      const expires = flag.has('expires') ? new Date(Date.now() + parseTtl(flag.get('expires')!)).toISOString() : undefined;
      const { code, record } = codes.add({
        label: (flag.get('label') ?? audiences.join(' + ')).slice(0, 60),
        audiences,
        scopes,
        ...(maxUses ? { maxUses } : {}),
        ...(expires ? { expires } : {}),
      });
      console.error(`[hn] ${record.id} "${record.label}" → ${audiences.join(', ')} [${scopes.join(' ') || 'no scopes'}]` +
        `${maxUses ? ` · ${maxUses} uses` : ' · unlimited uses'}${expires ? ` · redeem by ${expires.slice(0, 16)}Z` : ''}`);
      console.error(`[hn] the code (shown once — hand it out; it can also ride a link: ${cfg.publicUrl}/login?audience=${audiences[0]}#code=<code>):`);
      console.log(code);
      return;
    }
    case 'ls': {
      const all = codes.all();
      console.log(`codes (${all.length}):`);
      for (const c of all) {
        console.log(`  ${c.id}  "${c.label}"  → ${c.audiences.join(', ')} [${c.scopes.join(' ')}]  uses ${c.uses}${c.maxUses ? `/${c.maxUses}` : ''}` +
          `${c.expires ? `  until ${c.expires.slice(0, 16)}Z` : ''}${c.revoked ? '  [REVOKED]' : c.closed ? '  [closed]' : ''}`);
        for (const r of c.redeemed) console.log(`      ${r.at.slice(0, 16)}Z  ${r.sub}`);
      }
      return;
    }
    case 'close':
    case 'revoke': {
      if (!id) die(`usage: hn code ${sub} <id>`);
      const c = codes.set(id, sub === 'close' ? { closed: true } : { closed: true, revoked: true }) ?? die(`no code ${id}`);
      console.error(`[hn] ${c.id} ${sub === 'close' ? 'closed — no new redemptions; the ' + c.uses + ' who redeemed it keep access' : 'revoked — closed, and the access it gave is gone at each holder’s next sign-in'}`);
      return;
    }
    default:
      die('usage: hn code add | ls | close | revoke');
  }
}

main();
