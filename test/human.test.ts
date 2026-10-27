/**
 * End to end over HTTP: a real HomeNode on a random port, Discord faked at
 * the fetch seam, passkeys from a software authenticator.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HomeNode, type ServerConfig } from '../src/server.js';
import { verifyToken, type Aid1Payload } from '../src/token.js';
import { hashPassword, newSetupCode, normalizeRecovery, sha256hex } from '../src/accounts.js';
import { base32Decode, hotp, totpStep } from '../src/totp.js';
import { SoftAuthenticator } from './helpers/authenticator.js';
import { generateKey } from '../src/keys.js';
import { makeEnrollRequest } from '../src/statements.js';

const ORIGIN = 'https://id.test';
let node: HomeNode;
let base: string;
let ipSeq = 0;
let recoveryCodes: string[] = [];
// The Discord user the fake OAuth returns next.
let discordUser = { id: '42', username: 'dee', global_name: 'Dee' };
let discordRoles: string[] | null = ['r-member'];

function fakeDiscord(): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = String(input);
    const ok = (body: unknown) => new Response(JSON.stringify(body), { status: 200 });
    if (url.endsWith('/oauth2/token')) return ok({ access_token: 't', token_type: 'Bearer' });
    if (url.endsWith('/users/@me')) return ok(discordUser);
    if (url.includes('/member') || url.includes('/members/')) {
      return discordRoles ? ok({ roles: discordRoles, nick: null, user: discordUser }) : new Response('{}', { status: 404 });
    }
    return new Response('nope', { status: 500 });
  }) as typeof fetch;
}

function makeNode(extra: Partial<ServerConfig> = {}): HomeNode {
  const dir = mkdtempSync(join(tmpdir(), 'hn-human-'));
  writeFileSync(join(dir, 'roles.json'), JSON.stringify({
    guildId: 'g1',
    map: { 'r-member': { scopes: ['worlds:join', 'worlds:spectate'] }, 'r-orrery': { scopes: ['orrery:use'] } },
  }));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({
    principals: [{ sub: 'agent:fable@id.test', name: 'Fable', kind: 'agent', key: null, scopes: [] }],
  }));
  writeFileSync(join(dir, 'audiences.json'), JSON.stringify({
    eidoverse: { redirect: 'https://worlds.test/auth', requiredScopes: ['worlds:join'] },
    orrery: { redirect: 'https://orrery.test/auth', requiredScopes: ['orrery:use'] },
  }));
  return new HomeNode({
    iss: 'id.test', publicUrl: ORIGIN, bind: '127.0.0.1', port: 0, dataDir: dir, configDir: dir,
    discordClientId: 'cid', discordClientSecret: 'secret', ...extra,
  }, { fetchImpl: fakeDiscord() });
}

before(async () => {
  node = makeNode();
  base = `http://127.0.0.1:${await node.start()}`;
});
after(() => node.stop());

// Each request from its own address so the per-IP limiter stays out of the way.
const hdrs = (extra: Record<string, string> = {}) => ({ 'x-real-ip': `10.0.${ipSeq >> 8 & 255}.${ipSeq++ & 255}`, ...extra });

async function get(path: string, b = base, extra: Record<string, string> = {}) {
  const r = await fetch(b + path, { headers: hdrs(extra), redirect: 'manual' });
  return { status: r.status, text: await r.text(), location: r.headers.get('location'), headers: r.headers };
}
async function post(path: string, body: unknown, token?: string, b = base) {
  const r = await fetch(b + path, {
    method: 'POST', body: JSON.stringify(body),
    headers: hdrs({ 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) }),
  });
  return { status: r.status, body: (await r.json()) as Record<string, any>, cookie: (r.headers.get('set-cookie') ?? '').split(';')[0]! };
}

async function loginState(audience: string, b = base): Promise<string> {
  const r = await get(`/login?audience=${audience}`, b);
  assert.equal(r.status, 200);
  return /"state":"([^"]+)"/.exec(r.text)![1]!;
}
function tokenFrom(redirect: string, aud: string, n = node): Aid1Payload {
  const tok = /#token=(.+)$/.exec(redirect)![1]!;
  const v = verifyToken(tok, { issuerId: n.issuer.id, iss: 'id.test', aud });
  assert.ok(v.ok, !v.ok ? v.reason : '');
  return v.payload;
}
const rawToken = (redirect: string) => /#token=(.+)$/.exec(redirect)![1]!;

async function passwordLogin(username: string, password: string, audience: string, b = base) {
  return post('/login/password', { state: await loginState(audience, b), username, password }, undefined, b);
}
async function accountToken(username: string, password: string): Promise<string> {
  const r = await passwordLogin(username, password, 'account');
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return rawToken(r.body.redirect);
}
async function discordLogin(audience: string, b = base) {
  const start = await get(`/login?audience=${audience}&via=discord`, b);
  assert.equal(start.status, 302);
  const state = new URL(start.location!).searchParams.get('state')!;
  return get(`/oauth/callback?state=${state}&code=x`, b);
}

test('chooser page: CSP + no framing, unknown audience refused', async () => {
  const r = await get('/login?audience=eidoverse');
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-security-policy')!, /frame-ancestors 'none'/);
  assert.match(r.headers.get('content-security-policy')!, /script-src 'nonce-/);
  assert.match(r.text, /Continue with Discord/);
  assert.equal((await get('/login?audience=nope')).status, 400);
});

test('local account: password login mints the same aid1 shape; wrong password / scope refused', async () => {
  await node.accounts.add({
    sub: 'human:local:alice', username: 'alice', password: await hashPassword('alice password 1'),
    scopes: ['worlds:join'], createdAt: new Date().toISOString(),
  });
  const ok = await passwordLogin('Alice', 'alice password 1', 'eidoverse');
  assert.equal(ok.status, 200);
  assert.match(ok.body.redirect, /^https:\/\/worlds\.test\/auth#token=aid1\./);
  const p = tokenFrom(ok.body.redirect, 'eidoverse');
  assert.equal(p.sub, 'human:local:alice');
  assert.equal(p.kind, 'human');
  assert.deepEqual(p.scopes, ['worlds:join']);
  assert.ok(p.jti && p.exp - p.iat === 600);

  assert.equal((await passwordLogin('alice', 'wrong password!', 'eidoverse')).status, 401);
  assert.equal((await passwordLogin('nobody', 'wrong password!', 'eidoverse')).status, 401);
  const noScope = await passwordLogin('alice', 'alice password 1', 'orrery');
  assert.equal(noScope.status, 403);
  assert.match(noScope.body.error, /missing orrery:use/);
});

test('login POSTs demand JSON (no cross-site form posts)', async () => {
  const r = await fetch(base + '/login/password', { method: 'POST', headers: hdrs({ 'content-type': 'application/x-www-form-urlencoded' }), body: 'a=b' });
  assert.equal(r.status, 415);
});

test('five wrong passwords lock that username for a while', async () => {
  await node.accounts.add({ sub: 'human:local:carol', username: 'carol', password: await hashPassword('carol password 1'), scopes: ['worlds:join'], createdAt: '' });
  for (let i = 0; i < 5; i++) assert.equal((await passwordLogin('carol', `nope nope ${i}!`, 'eidoverse')).status, 401);
  const locked = await passwordLogin('carol', 'carol password 1', 'eidoverse');
  assert.equal(locked.status, 429);
});

test('TOTP: set up from the account page, then required at password login; recovery codes are single-use', async () => {
  const tok = await accountToken('alice', 'alice password 1');
  const begin = await post('/account/totp/begin', {}, tok);
  assert.equal(begin.status, 200);
  assert.match(begin.body.uri, /^otpauth:\/\/totp\/id\.test%3Aalice\?secret=/);
  assert.match(begin.body.qr, /^<svg/);
  const secret = base32Decode(begin.body.secret)!;
  assert.equal((await post('/account/totp/confirm', { code: '000000' }, tok)).status, 400);
  const conf = await post('/account/totp/confirm', { code: hotp(secret, totpStep()) }, tok);
  assert.equal(conf.status, 200);
  assert.equal(conf.body.recoveryCodes.length, 10);
  assert.equal(conf.body.totp.recoveryLeft, 10);

  // password alone is no longer enough
  const step1 = await passwordLogin('alice', 'alice password 1', 'eidoverse');
  assert.equal(step1.body.next, 'totp');
  assert.equal(step1.body.redirect, undefined);
  assert.equal((await post('/login/totp', { ticket: step1.body.ticket, code: '123456' })).status, 401);
  // the code used to confirm can't be replayed; the next step's code works
  assert.equal((await post('/login/totp', { ticket: step1.body.ticket, code: hotp(secret, totpStep()) })).status, 401);
  const step2 = await post('/login/totp', { ticket: step1.body.ticket, code: hotp(secret, totpStep() + 1) });
  assert.equal(step2.status, 200, JSON.stringify(step2.body));
  assert.equal(tokenFrom(step2.body.redirect, 'eidoverse').sub, 'human:local:alice');
  assert.equal((await post('/login/totp', { ticket: step1.body.ticket, code: hotp(secret, totpStep() + 1) })).status, 400); // ticket spent

  recoveryCodes = conf.body.recoveryCodes;
  const rc = conf.body.recoveryCodes[0];
  const t2 = await passwordLogin('alice', 'alice password 1', 'eidoverse');
  assert.equal((await post('/login/totp', { ticket: t2.body.ticket, code: rc.toUpperCase() })).status, 200);
  const t3 = await passwordLogin('alice', 'alice password 1', 'eidoverse');
  assert.equal((await post('/login/totp', { ticket: t3.body.ticket, code: rc })).status, 401);
  assert.equal(node.accounts.byUsername('alice')!.recovery!.length, 9);
});

test('passkeys: register on the account page, then sign in usernameless — no TOTP step', async () => {
  // alice has TOTP on (previous test): through it with a recovery code
  const s = await passwordLogin('alice', 'alice password 1', 'account');
  const t = await post('/login/totp', { ticket: s.body.ticket, code: recoveryCodes[1] });
  assert.equal(t.status, 200, JSON.stringify(t.body));
  const tok = rawToken(t.body.redirect);

  const auth = new SoftAuthenticator(-7, ORIGIN, 'id.test', { counting: true });
  const begin = await post('/account/passkeys/begin', {}, tok);
  assert.equal(begin.body.publicKey.rp.id, 'id.test');
  assert.equal(begin.body.publicKey.authenticatorSelection.userVerification, 'required');
  const fin = await post('/account/passkeys/finish', { credential: auth.create(begin.body.publicKey), name: 'laptop' }, tok);
  assert.equal(fin.status, 200, JSON.stringify(fin.body));
  assert.deepEqual(fin.body.passkeys.map((p: { name: string }) => p.name), ['laptop']);

  // a challenge is single-use
  const replay = await post('/account/passkeys/finish', { credential: auth.create(begin.body.publicKey) }, tok);
  assert.equal(replay.status, 400);

  const state = await loginState('eidoverse');
  const opts = await post('/login/passkey/begin', { state });
  assert.deepEqual(opts.body.publicKey.allowCredentials, []);
  const done = await post('/login/passkey/finish', { state, credential: auth.get(opts.body.publicKey) });
  assert.equal(done.status, 200, JSON.stringify(done.body));
  assert.equal(tokenFrom(done.body.redirect, 'eidoverse').sub, 'human:local:alice');
  assert.equal(node.accounts.byUsername('alice')!.passkeys![0]!.signCount, auth.signCount);

  // the login state was spent by that success
  assert.equal((await post('/login/passkey/begin', { state })).status, 400);

  // an unknown authenticator, and a wrong-origin assertion, are refused
  const stranger = new SoftAuthenticator(-8, ORIGIN, 'id.test');
  const s2 = await loginState('eidoverse');
  const o2 = await post('/login/passkey/begin', { state: s2 });
  assert.equal((await post('/login/passkey/finish', { state: s2, credential: stranger.get(o2.body.publicKey) })).status, 401);
  const o3 = await post('/login/passkey/begin', { state: s2 });
  assert.equal((await post('/login/passkey/finish', { state: s2, credential: auth.get(o3.body.publicKey, { origin: 'https://evil.test' }) })).status, 401);
});

test('Discord person adds a password: same sub either way; roles come from the Discord snapshot', async () => {
  discordUser = { id: '42', username: 'dee', global_name: 'Dee' };
  discordRoles = ['r-member'];
  const d = await discordLogin('eidoverse');
  assert.equal(d.status, 302);
  assert.equal(tokenFrom(d.location!, 'eidoverse').sub, 'human:discord:42');
  assert.equal(node.accounts.byDiscord('42'), undefined); // no row until they want one

  const a = await discordLogin('account');
  const tok = rawToken(a.location!);
  const me = await get('/account/me'); // no bearer
  assert.equal(me.status, 401);
  const view = await fetch(base + '/account/me', { headers: hdrs({ authorization: `Bearer ${tok}` }) }).then((r) => r.json());
  assert.equal(view.hasPassword, false);
  assert.equal(view.discord.canUnlink, false);

  assert.match((await post('/account/password', { username: 'fable', password: 'dee password 1' }, tok)).body.error, /taken|reserved/);
  const set = await post('/account/password', { username: 'Dee', password: 'dee password 1' }, tok);
  assert.equal(set.status, 200, JSON.stringify(set.body));
  assert.equal(set.body.username, 'dee');
  assert.equal(node.accounts.byDiscord('42')!.sub, 'human:discord:42');

  const pw = await passwordLogin('dee', 'dee password 1', 'eidoverse');
  assert.equal(pw.status, 200, JSON.stringify(pw.body));
  const p = tokenFrom(pw.body.redirect, 'eidoverse');
  assert.equal(p.sub, 'human:discord:42');
  assert.equal(p.name, 'Dee');
  assert.deepEqual(p.scopes.sort(), ['worlds:join', 'worlds:spectate']);

  // the anchor can't be unlinked
  assert.equal((await post('/account/discord/unlink', {}, tok)).status, 400);

  // a stale snapshot (no bot token to re-check) stops counting
  node.accounts.update('human:discord:42', (x) => ({ ...x, discord: { ...x.discord!, checkedAt: new Date(Date.now() - 8 * 86_400_000).toISOString() } }));
  const stale = await passwordLogin('dee', 'dee password 1', 'eidoverse');
  assert.equal(stale.status, 403);
  assert.match(stale.body.error, /sign in with Discord once/);
  // …and a Discord login refreshes it
  await discordLogin('eidoverse');
  assert.equal((await passwordLogin('dee', 'dee password 1', 'eidoverse')).status, 200);
});

test('a local account links Discord: Continue with Discord then opens it; one Discord, one account', async () => {
  await node.accounts.add({ sub: 'human:local:erin', username: 'erin', password: await hashPassword('erin password 1'), createdAt: '' });
  const tok = await accountToken('erin', 'erin password 1'); // no scopes: the account page still opens
  const link = await post('/account/discord/link', {}, tok);
  assert.equal(link.status, 200);
  assert.match(link.cookie, /^hn_link=/);
  const start = await get(new URL(link.body.url).pathname + new URL(link.body.url).search);
  assert.equal(start.status, 302);
  assert.match(start.location!, /^https:\/\/discord\.com\/oauth2\/authorize/);
  const state = new URL(start.location!).searchParams.get('state')!;

  discordUser = { id: '77', username: 'erin_dc', global_name: null as unknown as string };
  discordRoles = ['r-member', 'r-orrery'];
  const cb = await get(`/oauth/callback?state=${state}&code=x`, base, { cookie: link.cookie });
  assert.equal(cb.status, 302);
  assert.equal(tokenFrom(cb.location!, 'account').sub, 'human:local:erin');
  assert.equal(node.accounts.byUsername('erin')!.discord!.id, '77');

  const viaDiscord = await discordLogin('orrery');
  const p = tokenFrom(viaDiscord.location!, 'orrery');
  assert.equal(p.sub, 'human:local:erin');
  assert.equal(p.name, 'erin');
  assert.ok(p.scopes.includes('orrery:use'));

  // Discord 42 already belongs to dee's account
  const tok2 = await accountToken('erin', 'erin password 1');
  await post('/account/discord/unlink', {}, tok2);
  const link2 = await post('/account/discord/link', {}, tok2);
  const st2 = new URL(link2.body.url).searchParams.get('state')!;
  discordUser = { id: '42', username: 'dee', global_name: 'Dee' };
  assert.equal((await get(`/oauth/callback?state=${st2}&code=x`, base, { cookie: link2.cookie })).status, 409);
});

test('a Discord-link URL handed to someone else links nothing (bound to the browser that asked)', async () => {
  await node.accounts.add({ sub: 'human:local:mallory', username: 'mallory', password: await hashPassword('mallory password 1'), createdAt: '' });
  const tok = await accountToken('mallory', 'mallory password 1');
  const link = await post('/account/discord/link', {}, tok);
  const state = new URL(link.body.url).searchParams.get('state')!;
  // the victim opens the URL and completes Discord in THEIR browser (no hn_link cookie)
  discordUser = { id: '999', username: 'victim', global_name: 'Victim' };
  discordRoles = ['r-member', 'r-orrery'];
  const cb = await get(`/oauth/callback?state=${state}&code=x`);
  assert.equal(cb.status, 403);
  assert.match(cb.text, /same browser/);
  assert.equal(node.accounts.byUsername('mallory')!.discord, undefined);
  assert.equal(node.accounts.byDiscord('999'), undefined);
  // a wrong cookie is no better
  const link2 = await post('/account/discord/link', {}, tok);
  const st2 = new URL(link2.body.url).searchParams.get('state')!;
  assert.equal((await get(`/oauth/callback?state=${st2}&code=x`, base, { cookie: 'hn_link=guess' })).status, 403);
});

test('setup link: sets the password once, lands on the account page; 2FA still guards a reset', async () => {
  const { code, setup } = newSetupCode();
  await node.accounts.add({ sub: 'human:local:frank', username: 'frank', scopes: ['worlds:join'], setup, createdAt: '' });
  const info = await post('/account/setup/info', { code });
  assert.deepEqual(info.body, { username: 'frank', name: 'frank', needsTotp: false, needsUsername: false });
  assert.equal((await post('/account/setup', { code, password: 'short' })).status, 400);
  const done = await post('/account/setup', { code, password: 'frank password 1' });
  assert.equal(done.status, 200);
  assert.equal(tokenFrom(done.body.redirect, 'account').sub, 'human:local:frank');
  assert.equal((await post('/account/setup/info', { code })).status, 404); // spent
  assert.equal((await passwordLogin('frank', 'frank password 1', 'eidoverse')).status, 200);

  // reset link for alice (TOTP on): needs a code too
  const r = newSetupCode();
  node.accounts.update('human:local:alice', (a) => ({ ...a, setup: r.setup }));
  assert.equal((await post('/account/setup/info', { code: r.code })).body.needsTotp, true);
  assert.equal((await post('/account/setup', { code: r.code, password: 'alice password 2' })).status, 401);
});

test('disabling an account mid-sign-in stops a pending TOTP step', async () => {
  const totpAcct = node.accounts.byUsername('alice')!;
  const step1 = await passwordLogin('alice', 'alice password 1', 'eidoverse');
  assert.equal(step1.body.next, 'totp');
  node.accounts.update(totpAcct.sub, (a) => ({ ...a, disabled: true }));
  const r = await post('/login/totp', { ticket: step1.body.ticket, code: recoveryCodes[2] });
  assert.equal(r.status, 403);
  assert.equal(r.body.redirect, undefined);
  node.accounts.update(totpAcct.sub, (a) => ({ ...a, disabled: false }));
  // refused before the code was checked, so the recovery code is still unused
  assert.ok(node.accounts.byUsername('alice')!.recovery!.includes(sha256hex(normalizeRecovery(recoveryCodes[2]!))));
});

test('the 2FA lockout covers turning 2FA off and setup links, not just sign-in', async () => {
  const { code, setup } = newSetupCode();
  await node.accounts.add({ sub: 'human:local:ivan', username: 'ivan', scopes: ['worlds:join'], setup, createdAt: '' });
  const tok = rawToken((await post('/account/setup', { code, password: 'ivan password 1' })).body.redirect);
  const begin = await post('/account/totp/begin', {}, tok);
  const secret = base32Decode(begin.body.secret)!;
  await post('/account/totp/confirm', { code: hotp(secret, totpStep()) }, tok);
  for (let i = 0; i < 10; i++) assert.equal((await post('/account/totp/disable', { code: '000000' }, tok)).status, 400);
  // locked now — even the right code is refused, on every path
  assert.equal((await post('/account/totp/disable', { code: hotp(secret, totpStep() + 1) }, tok)).status, 429);
  const r = newSetupCode();
  node.accounts.update('human:local:ivan', (a) => ({ ...a, setup: r.setup }));
  assert.equal((await post('/account/setup', { code: r.code, password: 'ivan password 2', totp: hotp(secret, totpStep() + 1) })).status, 429);
  const t = await passwordLogin('ivan', 'ivan password 1', 'eidoverse');
  assert.equal((await post('/login/totp', { ticket: t.body.ticket, code: hotp(secret, totpStep() + 1) })).status, 429);
});

test('a setup link redeemed twice at once works once', async () => {
  const { code, setup } = newSetupCode();
  await node.accounts.add({ sub: 'human:local:judy', username: 'judy', scopes: ['worlds:join'], setup, createdAt: '' });
  const [a, b] = await Promise.all([
    post('/account/setup', { code, password: 'judy password one' }),
    post('/account/setup', { code, password: 'judy password two' }),
  ]);
  assert.deepEqual([a.status, b.status].sort(), [200, 404]);
  const winner = a.status === 200 ? 'judy password one' : 'judy password two';
  assert.equal((await passwordLogin('judy', winner, 'eidoverse')).status, 200);
});

test('two tabs registering passkeys at once: both passkeys sign in', async () => {
  const { code, setup } = newSetupCode();
  await node.accounts.add({ sub: 'human:local:kim', username: 'kim', scopes: ['worlds:join'], setup, createdAt: '' });
  const tok = rawToken((await post('/account/setup', { code, password: 'kim password 1' })).body.redirect);
  const [b1, b2] = await Promise.all([post('/account/passkeys/begin', {}, tok), post('/account/passkeys/begin', {}, tok)]);
  assert.equal(b1.body.publicKey.user.id, b2.body.publicKey.user.id);
  const k1 = new SoftAuthenticator(-7, ORIGIN, 'id.test');
  const k2 = new SoftAuthenticator(-257, ORIGIN, 'id.test');
  assert.equal((await post('/account/passkeys/finish', { credential: k1.create(b1.body.publicKey) }, tok)).status, 200);
  assert.equal((await post('/account/passkeys/finish', { credential: k2.create(b2.body.publicKey) }, tok)).status, 200);
  for (const k of [k1, k2]) {
    const state = await loginState('eidoverse');
    const opts = await post('/login/passkey/begin', { state });
    const done = await post('/login/passkey/finish', { state, credential: k.get(opts.body.publicKey) });
    assert.equal(done.status, 200, JSON.stringify(done.body));
  }
});

test('a person may take their own display name as their username', async () => {
  await node.accounts.add({
    sub: 'human:discord:43', name: 'zed',
    discord: { id: '43', name: 'Zed', grant: { scopes: ['worlds:join'] }, checkedAt: new Date().toISOString() },
    createdAt: '',
  });
  discordUser = { id: '43', username: 'zed_dc', global_name: 'Zed' };
  discordRoles = ['r-member'];
  const tok = rawToken((await discordLogin('account')).location!);
  const r = await post('/account/password', { username: 'Zed', password: 'zed password 1' }, tok);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.username, 'zed');
  // …but nobody else may
  discordUser = { id: '44', username: 'other', global_name: 'Other' };
  const tok2 = rawToken((await discordLogin('account')).location!);
  assert.match((await post('/account/password', { username: 'zed', password: 'other password 1' }, tok2)).body.error, /taken/);
});

test('wrong codes don’t touch the account file', async () => {
  const file = join(node.cfg.dataDir, 'accounts.json');
  const t = await passwordLogin('alice', 'alice password 1', 'eidoverse');
  assert.equal(t.body.next, 'totp');
  const before = { mtime: statSync(file).mtimeMs, body: readFileSync(file, 'utf8') };
  assert.equal((await post('/login/totp', { ticket: t.body.ticket, code: '000000' })).status, 401);
  assert.equal((await post('/login/totp', { ticket: t.body.ticket, code: 'zzzzz-zzzzz' })).status, 401);
  assert.equal(statSync(file).mtimeMs, before.mtime);
  assert.equal(readFileSync(file, 'utf8'), before.body);
});

test('an agent can’t enroll under a person’s username', async () => {
  const inv = node.invites.mint({ scopes: ['worlds:join'], maxUses: 1 });
  const key = generateKey();
  const r = await post('/enroll', makeEnrollRequest(key.privateKey, key.id, 'id.test', inv.code, 'Alice'));
  assert.equal(r.status, 403);
  assert.match(r.body.error, /name taken/);
});

test('disabled accounts get nothing, by any method; account API refuses foreign tokens', async () => {
  const consoleTok = rawToken((await passwordLogin('frank', 'frank password 1', 'console')).body.redirect);
  assert.equal((await post('/account/totp/begin', {}, consoleTok)).status, 401);

  node.accounts.update('human:discord:42', (a) => ({ ...a, disabled: true }));
  assert.equal((await passwordLogin('dee', 'dee password 1', 'eidoverse')).status, 403);
  discordUser = { id: '42', username: 'dee', global_name: 'Dee' };
  assert.equal((await discordLogin('eidoverse')).status, 403);
  node.accounts.update('human:discord:42', (a) => ({ ...a, disabled: false }));
});

test('can’t remove the last way in', async () => {
  const auth = new SoftAuthenticator(-8, ORIGIN, 'id.test');
  const { code, setup } = newSetupCode();
  await node.accounts.add({ sub: 'human:local:gail', username: 'gail', scopes: ['worlds:join'], setup, createdAt: '' });
  const tok = rawToken((await post('/account/setup', { code, password: 'gail password 1' })).body.redirect);
  const b = await post('/account/passkeys/begin', {}, tok);
  await post('/account/passkeys/finish', { credential: auth.create(b.body.publicKey) }, tok);
  node.accounts.update('human:local:gail', (a) => { const { password: _p, ...rest } = a; return rest; });
  const id = node.accounts.byUsername('gail')!.passkeys![0]!.id;
  const rm = await post('/account/passkeys/remove', { id }, tok);
  assert.equal(rm.status, 400);
  assert.match(rm.body.error, /only way/);
});

test('with a bot token, password logins re-check Discord roles live', async () => {
  const n2 = makeNode({ discordBotToken: 'BOT' });
  const b2 = `http://127.0.0.1:${await n2.start()}`;
  try {
    await n2.accounts.add({
      sub: 'human:discord:500', username: 'hank', password: await hashPassword('hank password 1'),
      discord: { id: '500', name: 'Hank', grant: { scopes: ['worlds:join'] }, checkedAt: new Date(0).toISOString() },
      createdAt: '',
    });
    discordUser = { id: '500', username: 'hank', global_name: 'Hank Live' };
    discordRoles = ['r-member', 'r-orrery'];
    const r = await passwordLogin('hank', 'hank password 1', 'orrery', b2);
    assert.equal(r.status, 200, JSON.stringify(r.body));
    const p = tokenFrom(r.body.redirect, 'orrery', n2);
    assert.ok(p.scopes.includes('orrery:use'));
    assert.equal(p.name, 'Hank Live');
    discordRoles = null; // left the guild
    assert.equal((await passwordLogin('hank', 'hank password 1', 'eidoverse', b2)).status, 403);
  } finally {
    n2.stop();
  }
});
