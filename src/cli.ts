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
 */
import { join } from 'node:path';
import { loadOrCreateIssuerKey } from './keys.js';
import { mintToken, parseTtl, type Aid1Payload, type PrincipalKind } from './token.js';
import { InviteStore, MintLog, PrincipalStore, type Principal } from './stores.js';
import { configFromEnv, HomeNode } from './server.js';

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
    case 'mint': {
      const name = flag.get('name') ?? die('--name required');
      const aud = flag.get('aud') ?? die('--aud required');
      const ttl = flag.get('ttl') ?? '72h';
      const kind = (flag.get('kind') ?? 'agent') as PrincipalKind;
      let p = principals.all().find((x) => x.name.toLowerCase() === name.toLowerCase());
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
      die(`unknown command "${cmd}" — serve | fingerprint | mint | invite | ls | revoke | revoke-invite`);
  }
}

main();
