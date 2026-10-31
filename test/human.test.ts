/**
 * End to end over HTTP: a real HomeNode on a random port, Discord faked at
 * the fetch seam, passkeys from a software authenticator.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
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
// The Google account the fake OIDC returns next, and the last token request it saw.
let googleUser: Record<string, unknown> = { sub: 'g-1', email: 'gail@gmail.com', email_verified: true, name: 'Gail' };
let googleTokenBody: URLSearchParams | null = null;
const b64j = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');

function fakeDiscord(): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const ok = (body: unknown) => new Response(JSON.stringify(body), { status: 200 });
    if (url === 'https://oauth2.googleapis.com/token') {
      googleTokenBody = new URLSearchParams(String(init?.body ?? ''));
      const claims = { iss: 'https://accounts.google.com', aud: 'gcid', exp: Math.floor(Date.now() / 1000) + 300, ...googleUser };
      return ok({ access_token: 'ga', id_token: `${b64j({ alg: 'RS256' })}.${b64j(claims)}.sig` });
    }
    if (url.endsWith('/oauth2/token')) return ok({ access_token: 't', token_type: 'Bearer' });
    if (url.endsWith('/users/@me')) return ok(discordUser);
    if (url.includes('/member') || url.includes('/members/')) {
      return discordRoles ? ok({ roles: discordRoles, nick: null, user: discordUser }) : new Response('{}', { status: 404 });
    }
    return new Response('nope', { status: 500 });
  }) as typeof fetch;
}

function makeNode(extra: Partial<ServerConfig> = {}, audiences?: Record<string, unknown>): HomeNode {
  const dir = mkdtempSync(join(tmpdir(), 'hn-human-'));
  writeFileSync(join(dir, 'roles.json'), JSON.stringify({
    guildId: 'g1',
    map: { 'r-member': { scopes: ['worlds:join', 'worlds:spectate'] }, 'r-orrery': { scopes: ['orrery:use'] } },
  }));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({
    principals: [{ sub: 'agent:fable@id.test', name: 'Fable', kind: 'agent', key: null, scopes: [] }],
  }));
  copyFileSync(join(import.meta.dirname, '..', 'config', 'invite-policy.example.json'), join(dir, 'invite-policy.json'));
  writeFileSync(join(dir, 'audiences.json'), JSON.stringify(audiences ?? {
    eidoverse: { redirect: 'https://worlds.test/auth', requiredScopes: ['worlds:join'] },
    orrery: { redirect: 'https://orrery.test/auth', requiredScopes: ['orrery:use'] },
    // no requiredScopes: open to any grant — what a code must NOT widen into
    ranker: { redirect: 'https://ranker.test/auth' },
    // open to newcomers
    notes: { redirect: 'https://notes.test/auth', requiredScopes: ['notes:use'], signup: {} },
    gate: { redirect: 'https://gate.test/auth' },
  }));
  return new HomeNode({
    iss: 'id.test', publicUrl: ORIGIN, bind: '127.0.0.1', port: 0, dataDir: dir, configDir: dir,
    discordClientId: 'cid', discordClientSecret: 'secret', googleClientId: 'gcid', googleClientSecret: 'gsecret', ...extra,
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
async function googleLogin(audience: string, b = base) {
  const start = await get(`/login?audience=${audience}&via=google`, b);
  assert.equal(start.status, 302);
  const state = new URL(start.location!).searchParams.get('state')!;
  return get(`/oauth/google/callback?state=${state}&code=x`, b);
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

// ── Google ──

test('Google: chooser offers it; the trip out is OIDC code flow with PKCE and only openid email profile', async () => {
  const page = await get('/login?audience=eidoverse');
  assert.match(page.text, /Continue with Google/);
  const start = await get('/login?audience=eidoverse&via=google');
  assert.equal(start.status, 302);
  const u = new URL(start.location!);
  assert.equal(u.origin + u.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
  assert.equal(u.searchParams.get('scope'), 'openid email profile');
  assert.equal(u.searchParams.get('redirect_uri'), 'https://id.test/oauth/google/callback');
  assert.equal(u.searchParams.get('code_challenge_method'), 'S256');
  // the verifier sent at the token step is the one the challenge was made from
  googleUser = { sub: 'g-nobody', email: 'nobody@gmail.com', email_verified: true };
  await get(`/oauth/google/callback?state=${u.searchParams.get('state')}&code=x`);
  const { createHash } = await import('node:crypto');
  assert.equal(createHash('sha256').update(googleTokenBody!.get('code_verifier')!).digest('base64url'), u.searchParams.get('code_challenge'));
  assert.equal(googleTokenBody!.get('client_secret'), 'gsecret');
});

test('Google: an unknown Google account gets nothing — an unverified one not even a row', async () => {
  // unverified address: no row, nothing opens (not even sign-in settings)
  googleUser = { sub: 'g-stranger', email: 'stranger@gmail.com', email_verified: false, name: 'Stranger' };
  const r = await googleLogin('eidoverse');
  assert.equal(r.status, 403);
  assert.match(r.text, /isn’t linked to an account here/);
  assert.equal(node.accounts.byGoogle('g-stranger'), undefined);
  assert.equal((await googleLogin('account')).status, 403);
  // verified (this node has an open audience): a row that holds nothing
  googleUser = { sub: 'g-stranger', email: 'stranger@gmail.com', email_verified: true, name: 'Stranger' };
  assert.equal((await googleLogin('eidoverse')).status, 403);
  assert.equal(node.accounts.byGoogle('g-stranger')!.scopes, undefined);
});

test('Google: an operator invite by address is claimed by the first VERIFIED sign-in, then follows the Google account', async () => {
  await node.accounts.add({
    sub: 'human:local:grace', username: 'grace', scopes: ['worlds:join'],
    google: { email: 'Grace.Hopper@gmail.com' }, createdAt: '',
  });
  // unverified address: no claim
  googleUser = { sub: 'g-grace', email: 'gracehopper@gmail.com', email_verified: false, name: 'Grace H' };
  assert.equal((await googleLogin('eidoverse')).status, 403);
  assert.equal(node.accounts.byUsername('grace')!.google!.sub, undefined);
  // verified, Gmail spelling differs only in dots/case: claimed
  googleUser = { sub: 'g-grace', email: 'gracehopper@gmail.com', email_verified: true, name: 'Grace H' };
  const ok = await googleLogin('eidoverse');
  assert.equal(ok.status, 302);
  const p = tokenFrom(ok.location!, 'eidoverse');
  assert.equal(p.sub, 'human:local:grace');
  assert.deepEqual(p.scopes, ['worlds:join']);
  assert.equal(node.accounts.byUsername('grace')!.google!.sub, 'g-grace');
  // later: a new address on the same Google account still signs in
  googleUser = { sub: 'g-grace', email: 'grace@navy.example', email_verified: true };
  assert.equal(tokenFrom((await googleLogin('eidoverse')).location!, 'eidoverse').sub, 'human:local:grace');
  assert.equal(node.accounts.byUsername('grace')!.google!.email, 'grace@navy.example');
  // a different Google account with the old address can't take it over
  googleUser = { sub: 'g-impostor', email: 'grace.hopper@gmail.com', email_verified: true };
  assert.equal((await googleLogin('eidoverse')).status, 403);
  // no scope for orrery: signed in, but refused there
  googleUser = { sub: 'g-grace', email: 'grace@navy.example', email_verified: true };
  assert.equal((await googleLogin('orrery')).status, 403);
  // disabled: refused
  node.accounts.update('human:local:grace', (a) => ({ ...a, disabled: true }));
  assert.equal((await googleLogin('eidoverse')).status, 403);
});

test('Google: link from sign-in settings (bound to this browser), then Continue with Google opens the account; unlink guarded', async () => {
  await node.accounts.add({ sub: 'human:local:hal', username: 'hal', password: await hashPassword('hal password 1'), scopes: ['worlds:join'], createdAt: '' });
  const tok = await accountToken('hal', 'hal password 1');
  const view0 = JSON.parse((await get('/account/me', base, { authorization: `Bearer ${tok}` })).text);
  assert.equal(view0.canLinkGoogle, true);

  // someone else completing the link URL in their browser links nothing
  const stolen = await post('/account/google/link', {}, tok);
  const stolenStart = await get(new URL(stolen.body.url).pathname + new URL(stolen.body.url).search);
  const stolenState = new URL(stolenStart.location!).searchParams.get('state')!;
  googleUser = { sub: 'g-victim', email: 'victim@gmail.com', email_verified: true };
  assert.equal((await get(`/oauth/google/callback?state=${stolenState}&code=x`)).status, 403);
  assert.equal(node.accounts.byGoogle('g-victim'), undefined);

  const link = await post('/account/google/link', {}, tok);
  assert.equal(link.status, 200);
  assert.match(link.cookie, /^hn_link=/);
  const start = await get(new URL(link.body.url).pathname + new URL(link.body.url).search);
  assert.equal(start.status, 302);
  assert.match(start.location!, /^https:\/\/accounts\.google\.com\//);
  const state = new URL(start.location!).searchParams.get('state')!;
  // a Google link state is no good at the Discord callback
  assert.equal((await get(`/oauth/callback?state=${state}&code=x`, base, { cookie: link.cookie })).status, 403);

  const link2 = await post('/account/google/link', {}, tok);
  const start2 = await get(new URL(link2.body.url).pathname + new URL(link2.body.url).search);
  const state2 = new URL(start2.location!).searchParams.get('state')!;
  googleUser = { sub: 'g-hal', email: 'hal@example.org', email_verified: false, name: 'HAL' };
  const cb = await get(`/oauth/google/callback?state=${state2}&code=x`, base, { cookie: link2.cookie });
  assert.equal(cb.status, 302);
  assert.equal(tokenFrom(cb.location!, 'account').sub, 'human:local:hal');
  assert.equal(node.accounts.byGoogle('g-hal')!.sub, 'human:local:hal');

  // an explicit link doesn't need a verified address; sign-in is by Google id
  const viaGoogle = await googleLogin('eidoverse');
  assert.equal(tokenFrom(viaGoogle.location!, 'eidoverse').sub, 'human:local:hal');

  const tok2 = await accountToken('hal', 'hal password 1');
  const view = JSON.parse((await get('/account/me', base, { authorization: `Bearer ${tok2}` })).text);
  assert.deepEqual(view.google, { email: 'hal@example.org', linked: true });
  assert.equal(view.canLinkGoogle, false);
  assert.equal((await post('/account/google/link', {}, tok2)).status, 400); // already linked
  assert.equal((await post('/account/google/unlink', {}, tok2)).status, 200);
  assert.equal(node.accounts.byGoogle('g-hal'), undefined);
});

test('Google: a Google-only account can’t unlink its last way in; a Discord person can add Google', async () => {
  await node.accounts.add({ sub: 'human:local:ida', username: 'ida', scopes: ['worlds:join'], google: { email: 'ida@gmail.com' }, createdAt: '' });
  googleUser = { sub: 'g-ida', email: 'ida@gmail.com', email_verified: true };
  const tok = rawToken((await googleLogin('account')).location!);
  assert.equal((await post('/account/google/unlink', {}, tok)).status, 400);

  discordUser = { id: '4242', username: 'jo', global_name: 'Jo' };
  discordRoles = ['r-member'];
  const dtok = rawToken((await discordLogin('account')).location!);
  const link = await post('/account/google/link', {}, dtok);
  assert.equal(link.status, 200);
  const start = await get(new URL(link.body.url).pathname + new URL(link.body.url).search);
  const state = new URL(start.location!).searchParams.get('state')!;
  // Google account already linked to ida: refused
  assert.equal((await get(`/oauth/google/callback?state=${state}&code=x`, base, { cookie: link.cookie })).status, 409);
  const link2 = await post('/account/google/link', {}, dtok);
  const start2 = await get(new URL(link2.body.url).pathname + new URL(link2.body.url).search);
  const state2 = new URL(start2.location!).searchParams.get('state')!;
  googleUser = { sub: 'g-jo', email: 'jo@gmail.com', email_verified: true };
  assert.equal((await get(`/oauth/google/callback?state=${state2}&code=x`, base, { cookie: link2.cookie })).status, 302);
  // Google now opens the Discord-anchored account, with its Discord roles
  const p = tokenFrom((await googleLogin('eidoverse')).location!, 'eidoverse');
  assert.equal(p.sub, 'human:discord:4242');
  assert.ok(p.scopes.includes('worlds:join'));
});

test('Google: cancelled at Google, or no Google configured', async () => {
  const start = await get('/login?audience=eidoverse&via=google');
  const state = new URL(start.location!).searchParams.get('state')!;
  const r = await get(`/oauth/google/callback?state=${state}&error=access_denied`);
  assert.equal(r.status, 400);
  assert.match(r.text, /cancelled/);
  const n2 = makeNode({ googleClientId: undefined, googleClientSecret: undefined });
  const b2 = `http://127.0.0.1:${await n2.start()}`;
  try {
    assert.doesNotMatch((await get('/login?audience=eidoverse', b2)).text, /Continue with Google/);
    assert.equal((await get('/login?audience=eidoverse&via=google', b2)).status, 200); // falls back to the chooser
  } finally {
    n2.stop();
  }
});

// ── access codes ──

async function withCode(audience: string, code: string, via: 'google' | 'discord') {
  const state = await loginState(audience);
  const c = await post('/login/code', { state, code });
  if (c.status !== 200) return { code: c, cb: null };
  const start = await get(`/login/${via}?state=${state}`);
  assert.equal(start.status, 302);
  return { code: c, cb: await get(`${via === 'google' ? '/oauth/google/callback' : '/oauth/callback'}?state=${state}&code=x`) };
}

test('codes: a newcomer signs up with Google + a code; the code opens ONLY its own audiences', async () => {
  const { code, record } = node.codes.add({ label: 'Speaker ranker', audiences: ['ranker'], scopes: ['ranker:member'] });
  googleUser = { sub: 'g-new', email: 'newcomer@gmail.com', email_verified: true, name: 'New Comer' };
  // without the code: refused (the row this node makes for a verified newcomer holds nothing)
  assert.equal((await googleLogin('ranker')).status, 403);
  assert.equal(node.accounts.bySub('human:google:g-new')!.scopes, undefined);
  const { code: c, cb } = await withCode('ranker', code.toUpperCase().replace(/-/g, ' '), 'google'); // typed sloppily: still the code
  assert.equal(c.status, 200);
  assert.deepEqual(c.body, { label: 'Speaker ranker', audiences: ['ranker'] });
  assert.equal(cb!.status, 302);
  const p = tokenFrom(cb!.location!, 'ranker');
  assert.equal(p.sub, 'human:google:g-new');
  assert.equal(p.name, 'New Comer');
  assert.deepEqual(p.scopes, ['ranker:member']);
  assert.equal(node.codes.byId(record.id)!.uses, 1);
  // signing in again later needs no code
  assert.equal(tokenFrom((await googleLogin('ranker')).location!, 'ranker').sub, 'human:google:g-new');
  // other audiences — even scope-less ones that take any grant — stay shut
  assert.equal((await googleLogin('gate')).status, 403);
  assert.equal((await googleLogin('eidoverse')).status, 403);
  // the account page opens, and lists the code
  const tok = rawToken((await googleLogin('account')).location!);
  const view = JSON.parse((await get('/account/me', base, { authorization: `Bearer ${tok}` })).text);
  assert.deepEqual(view.codes.map((x: { label: string }) => x.label), ['Speaker ranker']);
  // revoked: the access goes with it
  node.codes.set(record.id, { closed: true, revoked: true });
  assert.equal((await googleLogin('ranker')).status, 403);
});

test('codes: Discord newcomer outside the guild signs up with a code; limits, expiry, closing', async () => {
  const one = node.codes.add({ label: 'one seat', audiences: ['ranker'], scopes: [], maxUses: 1 });
  discordUser = { id: '8001', username: 'kit', global_name: 'Kit' };
  discordRoles = null; // not in the guild: no role grant at all
  assert.equal((await discordLogin('ranker')).status, 403);
  const first = await withCode('ranker', one.code, 'discord');
  assert.equal(first.cb!.status, 302);
  const p = tokenFrom(first.cb!.location!, 'ranker');
  assert.equal(p.sub, 'human:discord:8001');
  assert.deepEqual(p.scopes, []); // a code can grant an audience with no scopes at all
  // the same person again needs no code; redeeming it again is a no-op, not a second use
  assert.equal((await discordLogin('ranker')).status, 302);
  assert.notEqual(node.codes.redeem(one.code, 'human:discord:8001'), 'used up');
  assert.equal(node.codes.byId(one.record.id)!.uses, 1);
  // someone else: used up
  discordUser = { id: '8002', username: 'lee', global_name: 'Lee' };
  const second = await withCode('ranker', one.code, 'discord');
  assert.equal(second.code.status, 400);
  assert.match(second.code.body.error, /used up/);
  // wrong / expired / closed
  assert.match((await withCode('ranker', 'abcd-efgh-jkmn', 'discord')).code.body.error, /isn’t valid/);
  const old = node.codes.add({ label: 'old', audiences: ['ranker'], scopes: [], expires: new Date(Date.now() - 1000).toISOString() });
  assert.match((await withCode('ranker', old.code, 'discord')).code.body.error, /expired/);
  const shut = node.codes.add({ label: 'shut', audiences: ['ranker'], scopes: [] });
  node.codes.set(shut.record.id, { closed: true });
  assert.match((await withCode('ranker', shut.code, 'discord')).code.body.error, /no longer accepted/);
  // closing keeps what was given: kit still gets in
  node.codes.set(one.record.id, { closed: true });
  discordUser = { id: '8001', username: 'kit', global_name: 'Kit' };
  assert.equal((await discordLogin('ranker')).status, 302);
  discordRoles = ['r-member'];
});

test('codes: redeemed under sign-in settings, or riding a password sign-in', async () => {
  await node.accounts.add({ sub: 'human:local:mo', username: 'mo', password: await hashPassword('mo password 11'), createdAt: '' });
  const { code } = node.codes.add({ label: 'Ranker', audiences: ['ranker'], scopes: ['ranker:member'] });
  assert.equal((await passwordLogin('mo', 'mo password 11', 'ranker')).status, 403); // no grant yet
  const tok = await accountToken('mo', 'mo password 11');
  assert.equal((await post('/account/code', { code: 'nope-nope-nope' }, tok)).status, 400);
  const r = await post('/account/code', { code }, tok);
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.redeemed, { label: 'Ranker', audiences: ['ranker'] });
  assert.equal(r.body.codes.length, 1);
  const ok = await passwordLogin('mo', 'mo password 11', 'ranker');
  assert.equal(ok.status, 200);
  assert.deepEqual(tokenFrom(ok.body.redirect, 'ranker').scopes, ['ranker:member']);

  await node.accounts.add({ sub: 'human:local:nia', username: 'nia', password: await hashPassword('nia password 11'), createdAt: '' });
  const state = await loginState('ranker');
  assert.equal((await post('/login/code', { state, code })).status, 200);
  const viaPw = await post('/login/password', { state, username: 'nia', password: 'nia password 11' });
  assert.equal(viaPw.status, 200);
  assert.equal(tokenFrom(viaPw.body.redirect, 'ranker').sub, 'human:local:nia');
  assert.equal(node.accounts.bySub('human:local:nia')!.codes!.length, 1);
});

// ── per-person restrictions ──

test('restrict: roles set aside for one person don’t count; withheld scopes never come, even from a code', async () => {
  await node.accounts.add({ sub: 'human:discord:9001', discord: { id: '9001' }, ignoreRoles: ['r-orrery'], createdAt: '' });
  discordUser = { id: '9001', username: 'ari', global_name: 'Ari' };
  discordRoles = ['r-member', 'r-orrery'];
  const e = await discordLogin('eidoverse');
  assert.equal(e.status, 302);
  assert.deepEqual(tokenFrom(e.location!, 'eidoverse').scopes.sort(), ['worlds:join', 'worlds:spectate']);
  assert.equal((await discordLogin('orrery')).status, 403); // r-orrery set aside
  // someone else with the same roles is unaffected
  discordUser = { id: '9002', username: 'bex', global_name: 'Bex' };
  assert.equal((await discordLogin('orrery')).status, 302);

  // withhold: gone whatever the source — roles or a code
  node.accounts.update('human:discord:9001', (a) => ({ ...a, withhold: ['worlds:join', 'ranker:member'] }));
  discordUser = { id: '9001', username: 'ari', global_name: 'Ari' };
  assert.equal((await discordLogin('eidoverse')).status, 403);
  const { code } = node.codes.add({ label: 'r', audiences: ['ranker'], scopes: ['ranker:member'] });
  const w = await withCode('ranker', code, 'discord');
  assert.equal(w.cb!.status, 302);
  assert.deepEqual(tokenFrom(w.cb!.location!, 'ranker').scopes.includes('ranker:member'), false);
  discordRoles = ['r-member'];
});

test('restrict: the live bot re-check on a password sign-in honours set-aside roles too', async () => {
  const n2 = makeNode({ discordBotToken: 'BOT' });
  const b2 = `http://127.0.0.1:${await n2.start()}`;
  try {
    await n2.accounts.add({
      sub: 'human:discord:9100', username: 'cass', password: await hashPassword('cass password 1'),
      discord: { id: '9100', name: 'Cass' }, ignoreRoles: ['r-orrery'], createdAt: '',
    });
    discordUser = { id: '9100', username: 'cass', global_name: 'Cass' };
    discordRoles = ['r-member', 'r-orrery'];
    assert.equal((await passwordLogin('cass', 'cass password 1', 'orrery', b2)).status, 403);
    assert.equal((await passwordLogin('cass', 'cass password 1', 'eidoverse', b2)).status, 200);
  } finally {
    n2.stop();
    discordRoles = ['r-member'];
  }
});

// ── audiences open to newcomers ──

test('open audience: a Google newcomer signs up by signing in — for that audience only', async () => {
  const page = await get('/login?audience=notes');
  assert.match(page.text, /open to everyone/);
  assert.doesNotMatch((await get('/login?audience=eidoverse')).text, /open to everyone/);
  googleUser = { sub: 'g-open-1', email: 'reader@gmail.com', email_verified: true, name: 'Reader' };
  const r = await googleLogin('notes');
  assert.equal(r.status, 302);
  const p = tokenFrom(r.location!, 'notes');
  assert.equal(p.sub, 'human:google:g-open-1');
  assert.equal(p.name, 'Reader');
  assert.deepEqual(p.scopes, ['notes:use']);
  assert.ok(node.accounts.bySub('human:google:g-open-1'));
  // nowhere else — not even audiences that take any grant
  assert.equal((await googleLogin('gate')).status, 403);
  assert.equal((await googleLogin('eidoverse')).status, 403);
  assert.equal((await googleLogin('ranker')).status, 403);
});

test('open somewhere: a Google newcomer who starts at the wrong door gets an account, no access, and a pointer', async () => {
  // a closed audience: the row is made, it holds nothing, and the page says where to go
  googleUser = { sub: 'g-open-2', email: 'other@gmail.com', email_verified: true, name: 'Other' };
  const closed = await googleLogin('eidoverse');
  assert.equal(closed.status, 403);
  assert.match(closed.text, /signed in, but/);
  assert.match(closed.text, /Open to everyone: <a href="https:\/\/notes\.test">notes\.test<\/a>/);
  const row = node.accounts.bySub('human:google:g-open-2');
  assert.ok(row);
  assert.equal(row.scopes, undefined);
  assert.equal((await googleLogin('gate')).status, 403);
  assert.equal((await googleLogin('ranker')).status, 403);
  // the same person then goes to the open one: the same row, in
  const r = await googleLogin('notes');
  assert.equal(r.status, 302);
  assert.equal(tokenFrom(r.location!, 'notes').sub, 'human:google:g-open-2');

  // sign-in settings: a newcomer lands on their account page, which lists the open sites
  googleUser = { sub: 'g-open-3', email: 'third@gmail.com', email_verified: true, name: 'Third' };
  const acct = await googleLogin('account');
  assert.equal(acct.status, 302);
  const t = rawToken(acct.location!);
  const me = await get('/account/me', base, { authorization: `Bearer ${t}` });
  assert.equal(me.status, 200);
  const body = JSON.parse(me.text);
  assert.equal(body.sub, 'human:google:g-open-3');
  assert.deepEqual(body.open, [{ url: 'https://notes.test', host: 'notes.test' }]);
  assert.deepEqual(body.scopes, []);

  // a Discord account with no role, refused at a closed audience, gets the pointer too
  discordUser = { id: '7710', username: 'pia', global_name: 'Pia' };
  discordRoles = null;
  const d = await discordLogin('eidoverse');
  assert.equal(d.status, 403);
  assert.match(d.text, /Open to everyone: <a href="https:\/\/notes\.test">/);
  discordRoles = ['r-member'];
});

test('google.verified: recorded at sign-up, refreshed at each sign-in (what hn user add trusts)', async () => {
  googleUser = { sub: 'g-ver-1', email: 'ver@gmail.com', email_verified: true, name: 'Ver' };
  assert.equal((await googleLogin('notes')).status, 302);
  assert.equal(node.accounts.bySub('human:google:g-ver-1')!.google!.verified, true);
  // a row from before the flag existed gets it at its next verified sign-in
  node.accounts.update('human:google:g-ver-1', (a) => ({ ...a, google: { sub: a.google!.sub, email: a.google!.email, name: a.google!.name } }));
  assert.equal((await googleLogin('notes')).status, 302);
  assert.equal(node.accounts.bySub('human:google:g-ver-1')!.google!.verified, true);
  // Google stops vouching (a new, unverified address): the flag goes
  googleUser = { sub: 'g-ver-1', email: 'ver@elsewhere.example', email_verified: false, name: 'Ver' };
  assert.equal((await googleLogin('notes')).status, 302);
  const g = node.accounts.bySub('human:google:g-ver-1')!.google!;
  assert.equal(g.email, 'ver@elsewhere.example');
  assert.equal(g.verified, undefined);
});

test('open nowhere: a stranger’s Google sign-in still makes no row', async () => {
  const n2 = makeNode({}, { eidoverse: { redirect: 'https://worlds.test/auth', requiredScopes: ['worlds:join'] } });
  const b2 = `http://127.0.0.1:${await n2.start()}`;
  try {
    googleUser = { sub: 'g-closed-1', email: 'closed@gmail.com', email_verified: true };
    for (const aud of ['eidoverse', 'account']) {
      const r = await googleLogin(aud, b2);
      assert.equal(r.status, 403);
      assert.match(r.text, /isn’t linked to an account here/);
      assert.doesNotMatch(r.text, /Open to everyone/);
    }
    assert.equal(n2.accounts.bySub('human:google:g-closed-1'), undefined);
  } finally {
    n2.stop();
  }
});

test('open audience: a Discord account with no role gets in there and nowhere else; withhold still applies', async () => {
  discordUser = { id: '7700', username: 'nora', global_name: 'Nora' };
  discordRoles = null; // not in the guild
  const r = await discordLogin('notes');
  assert.equal(r.status, 302);
  assert.deepEqual(tokenFrom(r.location!, 'notes').scopes, ['notes:use']);
  assert.equal((await discordLogin('gate')).status, 403);
  // a person the operator withholds it from stays out
  await node.accounts.add({ sub: 'human:discord:7701', discord: { id: '7701' }, withhold: ['notes:use'], createdAt: '' });
  discordUser = { id: '7701', username: 'ozzy', global_name: 'Ozzy' };
  assert.equal((await discordLogin('notes')).status, 403);
  discordRoles = ['r-member'];
});
