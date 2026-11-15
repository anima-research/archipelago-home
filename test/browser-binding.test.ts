import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HomeNode, type ServerConfig } from '../src/server.js';
import { verifyToken, type Aid1Payload } from '../src/token.js';
import { hashPassword, newSetupCode } from '../src/accounts.js';
import { base32Decode, hotp, totpStep } from '../src/totp.js';
import { SoftAuthenticator } from './helpers/authenticator.js';

const HTTPS_ORIGIN = 'https://id.test';
let node: HomeNode;
let base: string;
let ipSeq = 0;
let discordUser = { id: '4201', username: 'dana', global_name: 'Dana' };
let discordRoles: string[] | null = ['r-member'];
let googleUser: Record<string, unknown> = { sub: 'g-4201', email: 'dana@gmail.com', email_verified: true, name: 'Dana G' };

const b64j = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');

function fakeProviders(): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = String(input);
    const ok = (body: unknown) => new Response(JSON.stringify(body), { status: 200 });
    if (url === 'https://oauth2.googleapis.com/token') {
      const claims = { iss: 'https://accounts.google.com', aud: 'gcid', exp: Math.floor(Date.now() / 1000) + 300, ...googleUser };
      return ok({ access_token: 'ga', id_token: `${b64j({ alg: 'RS256' })}.${b64j(claims)}.sig` });
    }
    if (url.endsWith('/oauth2/token')) return ok({ access_token: 't', token_type: 'Bearer' });
    if (url.endsWith('/users/@me')) return ok(discordUser);
    if (url.includes('/member') || url.includes('/members/')) {
      return discordRoles ? ok({ roles: discordRoles, nick: null, user: discordUser }) : new Response('{}', { status: 404 });
    }
    return new Response('unexpected fetch', { status: 500 });
  }) as typeof fetch;
}

function makeTestNode(extra: Partial<ServerConfig> = {}): HomeNode {
  const dir = mkdtempSync(join(tmpdir(), 'hn-bind-'));
  writeFileSync(join(dir, 'roles.json'), JSON.stringify({
    guildId: 'g1',
    map: { 'r-member': { scopes: ['worlds:join', 'worlds:spectate'] } },
  }));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({ principals: [] }));
  copyFileSync(join(import.meta.dirname, '..', 'config', 'invite-policy.example.json'), join(dir, 'invite-policy.json'));
  writeFileSync(join(dir, 'audiences.json'), JSON.stringify({
    eidoverse: { redirect: 'https://worlds.test/auth', requiredScopes: ['worlds:join'] },
    notes: { redirect: 'https://notes.test/auth', requiredScopes: ['notes:use'], signup: {} },
  }));
  return new HomeNode({
    iss: 'id.test',
    publicUrl: HTTPS_ORIGIN,
    bind: '127.0.0.1',
    port: 0,
    dataDir: dir,
    configDir: dir,
    discordClientId: 'cid',
    discordClientSecret: 'secret',
    googleClientId: 'gcid',
    googleClientSecret: 'gsecret',
    ...extra,
  }, { fetchImpl: fakeProviders() });
}

before(async () => {
  node = makeTestNode();
  base = `http://127.0.0.1:${await node.start()}`;
});
after(() => node.stop());

const nextHeaders = (extra: Record<string, string> = {}) => ({
  'x-real-ip': `10.9.${(ipSeq >> 8) & 255}.${ipSeq++ & 255}`,
  ...extra,
});
const cookiePair = (setCookieHeader: string | null) => (setCookieHeader ?? '').split(';')[0]!;
const rawToken = (redirect: string) => /#token=(.+)$/.exec(redirect)![1]!;

function verifyRedirectToken(redirect: string, aud: string, targetNode = node): Aid1Payload {
  const v = verifyToken(rawToken(redirect), { issuerId: targetNode.issuer.id, iss: 'id.test', aud });
  assert.ok(v.ok, !v.ok ? v.reason : '');
  return v.payload;
}

async function rawGet(path: string, extra: Record<string, string> = {}, b = base) {
  const r = await fetch(b + path, { headers: nextHeaders(extra), redirect: 'manual' });
  const setCookie = r.headers.get('set-cookie');
  return {
    status: r.status,
    text: await r.text(),
    location: r.headers.get('location'),
    setCookie,
    cookie: cookiePair(setCookie),
  };
}

async function rawPost(path: string, body: unknown, extra: Record<string, string> = {}, b = base) {
  const r = await fetch(b + path, {
    method: 'POST',
    body: JSON.stringify(body),
    headers: nextHeaders({ 'content-type': 'application/json', ...extra }),
  });
  const setCookie = r.headers.get('set-cookie');
  return {
    status: r.status,
    body: (await r.json()) as Record<string, any>,
    setCookie,
    cookie: cookiePair(setCookie),
  };
}

async function loginPageState(audience: string, extra: Record<string, string> = {}, b = base) {
  const r = await rawGet(`/login?audience=${encodeURIComponent(audience)}`, extra, b);
  assert.equal(r.status, 200);
  return { state: /"state":"([^"]+)"/.exec(r.text)![1]!, setCookie: r.setCookie, cookie: r.cookie };
}

test('Discord sign-in refuses a callback without the starting browser cookie, and two login states in one browser both finish', async () => {
  discordUser = { id: '4201', username: 'dana', global_name: 'Dana' };
  discordRoles = ['r-member'];

  const start1 = await rawGet('/login?audience=eidoverse&via=discord');
  assert.equal(start1.status, 302);
  const state1 = new URL(start1.location!).searchParams.get('state')!;
  const noCookie = await rawGet(`/oauth/callback?state=${state1}&code=x`);
  assert.equal(noCookie.status, 403);
  assert.equal(noCookie.location, null);
  assert.match(noCookie.text, /Signing in with Discord has to finish in the same browser that started it/);
  assert.match(noCookie.text, /href="\/login\?audience=eidoverse"/);
  assert.match(start1.setCookie ?? '', /^__Host-hn_browser=[A-Za-z0-9_-]{32}; Path=\/; Max-Age=600; HttpOnly; SameSite=Lax; Secure$/);

  const start2 = await rawGet('/login?audience=eidoverse&via=discord');
  const state2 = new URL(start2.location!).searchParams.get('state')!;
  const wrongCookie = await rawGet(`/oauth/callback?state=${state2}&code=x`, { cookie: `__Host-hn_browser=${'w'.repeat(32)}` });
  assert.equal(wrongCookie.status, 403);

  const badInput = await rawGet('/login?audience=eidoverse&via=discord', { cookie: '__Host-hn_browser=not-valid!' });
  assert.doesNotMatch(badInput.cookie, /not-valid/);
  assert.match(badInput.cookie, /^__Host-hn_browser=[A-Za-z0-9_-]{32}$/);
  const badInputState = new URL(badInput.location!).searchParams.get('state')!;
  const replacedOk = await rawGet(`/oauth/callback?state=${badInputState}&code=x`, { cookie: badInput.cookie });
  assert.equal(replacedOk.status, 302);
  assert.equal(verifyRedirectToken(replacedOk.location!, 'eidoverse').sub, 'human:discord:4201');

  const tab1 = await rawGet('/login?audience=eidoverse&via=discord');
  const tab2 = await rawGet('/login?audience=notes&via=discord', { cookie: tab1.cookie });
  assert.equal(tab2.cookie, tab1.cookie);
  const tab1State = new URL(tab1.location!).searchParams.get('state')!;
  const tab2State = new URL(tab2.location!).searchParams.get('state')!;
  const finish1 = await rawGet(`/oauth/callback?state=${tab1State}&code=x`, { cookie: tab1.cookie });
  const finish2 = await rawGet(`/oauth/callback?state=${tab2State}&code=x`, { cookie: tab1.cookie });
  assert.equal(finish1.status, 302);
  assert.equal(finish2.status, 302);
  assert.equal(verifyRedirectToken(finish1.location!, 'eidoverse').sub, 'human:discord:4201');
  assert.equal(verifyRedirectToken(finish2.location!, 'notes').sub, 'human:discord:4201');
});

test('Google sign-in refuses a callback without the starting browser cookie and finishes when that cookie returns', async () => {
  googleUser = { sub: 'g-4202', email: 'gus@gmail.com', email_verified: true, name: 'Gus' };

  const start1 = await rawGet('/login?audience=notes&via=google');
  assert.equal(start1.status, 302);
  const state1 = new URL(start1.location!).searchParams.get('state')!;
  const noCookie = await rawGet(`/oauth/google/callback?state=${state1}&code=x`);
  assert.equal(noCookie.status, 403);
  assert.equal(noCookie.location, null);
  assert.match(noCookie.text, /Signing in with Google has to finish in the same browser that started it/);
  assert.match(noCookie.text, /href="\/login\?audience=notes"/);
  assert.match(start1.setCookie ?? '', /^__Host-hn_browser=[A-Za-z0-9_-]{32}; Path=\/; Max-Age=600; HttpOnly; SameSite=Lax; Secure$/);

  const start2 = await rawGet('/login?audience=notes&via=google');
  const state2 = new URL(start2.location!).searchParams.get('state')!;
  const wrongCookie = await rawGet(`/oauth/google/callback?state=${state2}&code=x`, { cookie: `__Host-hn_browser=${'z'.repeat(32)}` });
  assert.equal(wrongCookie.status, 403);

  const start3 = await rawGet('/login?audience=notes&via=google');
  const state3 = new URL(start3.location!).searchParams.get('state')!;
  const ok = await rawGet(`/oauth/google/callback?state=${state3}&code=x`, { cookie: start3.cookie });
  assert.equal(ok.status, 302);
  assert.equal(verifyRedirectToken(ok.location!, 'notes').sub, 'human:google:g-4202');
});

test('linking Discord or Google after a setup link mints a browser cookie, refuses another browser, and leaves sibling states intact', async () => {
  const s1 = newSetupCode();
  node.accounts.add({ sub: 'human:local:lena', username: 'lena', scopes: ['worlds:join'], setup: s1.setup, createdAt: '' });
  const setup1 = await rawPost('/account/setup', { code: s1.code, password: 'lena password 1' });
  assert.equal(setup1.status, 200);
  const lenaTok = rawToken(setup1.body.redirect);
  const lenaAuth = { authorization: `Bearer ${lenaTok}`, ...(setup1.cookie ? { cookie: setup1.cookie } : {}) };

  const dLink1 = await rawPost('/account/discord/link', {}, lenaAuth);
  assert.equal(dLink1.status, 200);
  assert.match(dLink1.setCookie ?? '', /^__Host-hn_browser=[A-Za-z0-9_-]{32}; Path=\/; Max-Age=600; HttpOnly; SameSite=Lax; Secure$/);
  const dState1 = new URL(dLink1.body.url).searchParams.get('state')!;
  discordUser = { id: '5101', username: 'stranger', global_name: 'Stranger' };
  const otherBrowser = await rawGet(`/oauth/callback?state=${dState1}&code=x`);
  assert.equal(otherBrowser.status, 403);
  assert.match(otherBrowser.text, /Linking Discord has to finish in the same browser/);
  assert.equal(node.accounts.byUsername('lena')!.discord, undefined);

  const dLink2 = await rawPost('/account/discord/link', {}, { ...lenaAuth, cookie: [setup1.cookie, dLink1.cookie].filter(Boolean).join('; ') });
  assert.equal(dLink2.cookie, dLink1.cookie);
  const siblingLogin = await rawGet('/login?audience=notes&via=google', { cookie: dLink1.cookie });
  assert.equal(siblingLogin.cookie, dLink1.cookie);

  const dStart2 = await rawGet(new URL(dLink2.body.url).pathname + new URL(dLink2.body.url).search, { cookie: dLink1.cookie });
  assert.equal(dStart2.status, 302);
  const dState2 = new URL(dStart2.location!).searchParams.get('state')!;
  discordUser = { id: '5102', username: 'lena_dc', global_name: 'Lena' };
  const dDone = await rawGet(`/oauth/callback?state=${dState2}&code=x`, { cookie: dLink1.cookie });
  assert.equal(dDone.status, 302);
  const postLinkPayload = verifyRedirectToken(dDone.location!, 'account');
  assert.equal(postLinkPayload.sub, 'human:local:lena');
  assert.equal(dDone.cookie, `__Host-hn_account=${postLinkPayload.jti}`);
  assert.equal(node.accounts.byUsername('lena')!.discord!.id, '5102');
  assert.equal((await rawGet('/account/me', { authorization: `Bearer ${rawToken(dDone.location!)}`, cookie: dDone.cookie })).status, 200);

  googleUser = { sub: 'g-5103', email: 'sibling@gmail.com', email_verified: true, name: 'Sibling' };
  const siblingState = new URL(siblingLogin.location!).searchParams.get('state')!;
  const siblingFinish = await rawGet(`/oauth/google/callback?state=${siblingState}&code=x`, { cookie: dLink1.cookie });
  assert.equal(siblingFinish.status, 302);

  const s2 = newSetupCode();
  node.accounts.add({ sub: 'human:local:mira', username: 'mira', scopes: ['worlds:join'], setup: s2.setup, createdAt: '' });
  const setup2 = await rawPost('/account/setup', { code: s2.code, password: 'mira password 1' });
  const miraTok = rawToken(setup2.body.redirect);
  const miraAuth = { authorization: `Bearer ${miraTok}`, ...(setup2.cookie ? { cookie: setup2.cookie } : {}) };

  const gLink1 = await rawPost('/account/google/link', {}, miraAuth);
  assert.equal(gLink1.status, 200);
  assert.match(gLink1.setCookie ?? '', /^__Host-hn_browser=[A-Za-z0-9_-]{32}; Path=\/; Max-Age=600; HttpOnly; SameSite=Lax; Secure$/);
  const gStart1 = await rawGet(new URL(gLink1.body.url).pathname + new URL(gLink1.body.url).search, { cookie: gLink1.cookie });
  const gState1 = new URL(gStart1.location!).searchParams.get('state')!;
  assert.equal((await rawGet(`/oauth/google/callback?state=${gState1}&code=x`)).status, 403);
  assert.equal(node.accounts.byUsername('mira')!.google, undefined);

  const gLink2 = await rawPost('/account/google/link', {}, { ...miraAuth, cookie: [setup2.cookie, gLink1.cookie].filter(Boolean).join('; ') });
  const gStart2 = await rawGet(new URL(gLink2.body.url).pathname + new URL(gLink2.body.url).search, { cookie: gLink1.cookie });
  const gState2 = new URL(gStart2.location!).searchParams.get('state')!;
  googleUser = { sub: 'g-5104', email: 'mira@gmail.com', email_verified: true, name: 'Mira' };
  const gDone = await rawGet(`/oauth/google/callback?state=${gState2}&code=x`, { cookie: gLink1.cookie });
  assert.equal(gDone.status, 302);
  const miraPostLink = verifyRedirectToken(gDone.location!, 'account');
  assert.equal(gDone.cookie, `__Host-hn_account=${miraPostLink.jti}`);
  assert.equal(node.accounts.byUsername('mira')!.google!.sub, 'g-5104');
});

test('account tokens require their matching Strict cookie across issuance paths, and a second sign-in replaces the first', async () => {
  const setup = newSetupCode();
  node.accounts.add({ sub: 'human:local:nora', username: 'nora', scopes: ['worlds:join'], setup: setup.setup, createdAt: '' });

  const fromSetup = await rawPost('/account/setup', { code: setup.code, password: 'nora password 1' });
  assert.equal(fromSetup.status, 200);
  const tokSetup = rawToken(fromSetup.body.redirect);
  assert.equal((await rawGet('/account/me', { authorization: `Bearer ${tokSetup}` })).status, 401);
  assert.equal((await rawPost('/account/totp/begin', {}, { authorization: `Bearer ${tokSetup}` })).status, 401);
  assert.equal((await rawGet('/account/me', { authorization: `Bearer ${tokSetup}`, cookie: '__Host-hn_account=wrong' })).status, 401);

  const pSetup = verifyRedirectToken(fromSetup.body.redirect, 'account');
  assert.equal(fromSetup.setCookie, `__Host-hn_account=${pSetup.jti}; Path=/; Max-Age=600; HttpOnly; SameSite=Strict; Secure`);
  assert.equal((await rawGet('/account/me', { authorization: `Bearer ${tokSetup}`, cookie: fromSetup.cookie })).status, 200);

  const stPw = await loginPageState('account');
  const fromPw = await rawPost('/login/password', { state: stPw.state, username: 'nora', password: 'nora password 1' });
  assert.equal(fromPw.status, 200);
  const tokPw = rawToken(fromPw.body.redirect);
  const pPw = verifyRedirectToken(fromPw.body.redirect, 'account');
  assert.equal(fromPw.setCookie, `__Host-hn_account=${pPw.jti}; Path=/; Max-Age=600; HttpOnly; SameSite=Strict; Secure`);
  assert.equal((await rawGet('/account/me', { authorization: `Bearer ${tokSetup}`, cookie: fromPw.cookie })).status, 401);
  assert.equal((await rawGet('/account/me', { authorization: `Bearer ${tokPw}`, cookie: fromPw.cookie })).status, 200);

  const auth = new SoftAuthenticator(-7, HTTPS_ORIGIN, 'id.test');
  const pkBegin = await rawPost('/account/passkeys/begin', {}, { authorization: `Bearer ${tokPw}`, cookie: fromPw.cookie });
  assert.equal((await rawPost('/account/passkeys/finish', { credential: auth.create(pkBegin.body.publicKey), name: 'key1' }, { authorization: `Bearer ${tokPw}`, cookie: fromPw.cookie })).status, 200);

  const totpBegin = await rawPost('/account/totp/begin', {}, { authorization: `Bearer ${tokPw}`, cookie: fromPw.cookie });
  const secret = base32Decode(totpBegin.body.secret)!;
  assert.equal((await rawPost('/account/totp/confirm', { code: hotp(secret, totpStep()) }, { authorization: `Bearer ${tokPw}`, cookie: fromPw.cookie })).status, 200);

  const stTotp = await loginPageState('account');
  const step1 = await rawPost('/login/password', { state: stTotp.state, username: 'nora', password: 'nora password 1' });
  assert.equal(step1.body.next, 'totp');
  assert.equal(step1.setCookie, null);
  const fromTotp = await rawPost('/login/totp', { ticket: step1.body.ticket, code: hotp(secret, totpStep() + 1) });
  assert.equal(fromTotp.status, 200);
  const pTotp = verifyRedirectToken(fromTotp.body.redirect, 'account');
  assert.equal(fromTotp.setCookie, `__Host-hn_account=${pTotp.jti}; Path=/; Max-Age=600; HttpOnly; SameSite=Strict; Secure`);
  assert.equal((await rawGet('/account/me', { authorization: `Bearer ${rawToken(fromTotp.body.redirect)}`, cookie: fromTotp.cookie })).status, 200);

  const stPk = await loginPageState('account');
  const pkOpts = await rawPost('/login/passkey/begin', { state: stPk.state });
  const fromPk = await rawPost('/login/passkey/finish', { state: stPk.state, credential: auth.get(pkOpts.body.publicKey) });
  assert.equal(fromPk.status, 200);
  const pPk = verifyRedirectToken(fromPk.body.redirect, 'account');
  assert.equal(fromPk.setCookie, `__Host-hn_account=${pPk.jti}; Path=/; Max-Age=600; HttpOnly; SameSite=Strict; Secure`);
  assert.equal((await rawGet('/account/me', { authorization: `Bearer ${rawToken(fromPk.body.redirect)}`, cookie: fromPk.cookie })).status, 200);

  discordUser = { id: '6101', username: 'dora', global_name: 'Dora' };
  discordRoles = ['r-member'];
  const dStart = await rawGet('/login?audience=account&via=discord');
  const dCb = await rawGet(`/oauth/callback?state=${new URL(dStart.location!).searchParams.get('state')}&code=x`, { cookie: dStart.cookie });
  assert.equal(dCb.status, 302);
  const pDiscord = verifyRedirectToken(dCb.location!, 'account');
  assert.equal(dCb.setCookie, `__Host-hn_account=${pDiscord.jti}; Path=/; Max-Age=600; HttpOnly; SameSite=Strict; Secure`);
  assert.equal((await rawGet('/account/me', { authorization: `Bearer ${rawToken(dCb.location!)}`, cookie: dCb.cookie })).status, 200);

  googleUser = { sub: 'g-6102', email: 'gina@gmail.com', email_verified: true, name: 'Gina' };
  const gStart = await rawGet('/login?audience=account&via=google');
  const gCb = await rawGet(`/oauth/google/callback?state=${new URL(gStart.location!).searchParams.get('state')}&code=x`, { cookie: gStart.cookie });
  assert.equal(gCb.status, 302);
  const pGoogle = verifyRedirectToken(gCb.location!, 'account');
  assert.equal(gCb.setCookie, `__Host-hn_account=${pGoogle.jti}; Path=/; Max-Age=600; HttpOnly; SameSite=Strict; Secure`);
  assert.equal((await rawGet('/account/me', { authorization: `Bearer ${rawToken(gCb.location!)}`, cookie: gCb.cookie })).status, 200);
});

test('console tokens require their matching Strict cookie, external audiences set no page cookie, and http public URLs use plain cookie names', async () => {
  node.accounts.add({
    sub: 'human:local:owen',
    username: 'owen',
    password: await hashPassword('owen password 1'),
    scopes: ['worlds:join'],
    createdAt: '',
  });
  discordUser = { id: '7101', username: 'sponsor', global_name: 'Sponsor' };
  discordRoles = ['r-member'];

  const cStart = await rawGet('/login?audience=console&via=discord');
  const cCb = await rawGet(`/oauth/callback?state=${new URL(cStart.location!).searchParams.get('state')}&code=x`, { cookie: cStart.cookie });
  assert.equal(cCb.status, 302);
  const tokConsole1 = rawToken(cCb.location!);
  assert.equal((await rawGet('/console/me', { authorization: `Bearer ${tokConsole1}` })).status, 401);
  assert.equal((await rawGet('/console/invites', { authorization: `Bearer ${tokConsole1}` })).status, 401);
  assert.equal((await rawPost('/console/invites', { label: 'test' }, { authorization: `Bearer ${tokConsole1}` })).status, 401);

  const pConsole1 = verifyRedirectToken(cCb.location!, 'console');
  assert.equal(cCb.setCookie, `__Host-hn_console=${pConsole1.jti}; Path=/; Max-Age=600; HttpOnly; SameSite=Strict; Secure`);
  assert.equal((await rawGet('/console/me', { authorization: `Bearer ${tokConsole1}`, cookie: `__Host-hn_account=${pConsole1.jti}` })).status, 401);
  assert.equal((await rawGet('/console/me', { authorization: `Bearer ${tokConsole1}`, cookie: cCb.cookie })).status, 200);

  const stPw = await loginPageState('console');
  const cPw = await rawPost('/login/password', { state: stPw.state, username: 'owen', password: 'owen password 1' });
  assert.equal(cPw.status, 200);
  const tokConsole2 = rawToken(cPw.body.redirect);
  const pConsole2 = verifyRedirectToken(cPw.body.redirect, 'console');
  assert.equal(cPw.setCookie, `__Host-hn_console=${pConsole2.jti}; Path=/; Max-Age=600; HttpOnly; SameSite=Strict; Secure`);
  assert.equal((await rawGet('/console/me', { authorization: `Bearer ${tokConsole1}`, cookie: cPw.cookie })).status, 401);
  assert.equal((await rawGet('/console/me', { authorization: `Bearer ${tokConsole2}`, cookie: cPw.cookie })).status, 200);

  const extStart = await rawGet('/login?audience=eidoverse&via=discord');
  const extCb = await rawGet(`/oauth/callback?state=${new URL(extStart.location!).searchParams.get('state')}&code=x`, { cookie: extStart.cookie });
  assert.equal(extCb.status, 302);
  assert.equal(extCb.setCookie, null);
  const stExtPw = await loginPageState('eidoverse');
  const extPw = await rawPost('/login/password', { state: stExtPw.state, username: 'owen', password: 'owen password 1' });
  assert.equal(extPw.status, 200);
  assert.equal(extPw.setCookie, null);

  const httpNode = makeTestNode({ publicUrl: 'http://localhost' });
  const httpBase = `http://127.0.0.1:${await httpNode.start()}`;
  try {
    const hStart = await rawGet('/login?audience=console&via=discord', {}, httpBase);
    assert.match(hStart.setCookie ?? '', /^hn_browser=[A-Za-z0-9_-]{32}; Path=\/; Max-Age=600; HttpOnly; SameSite=Lax$/);
    const hCb = await rawGet(`/oauth/callback?state=${new URL(hStart.location!).searchParams.get('state')}&code=x`, { cookie: hStart.cookie }, httpBase);
    assert.equal(hCb.status, 302);
    const hp = verifyRedirectToken(hCb.location!, 'console', httpNode);
    assert.equal(hCb.setCookie, `hn_console=${hp.jti}; Path=/; Max-Age=600; HttpOnly; SameSite=Strict`);
    assert.equal((await rawGet('/console/me', { authorization: `Bearer ${rawToken(hCb.location!)}` }, httpBase)).status, 401);
    assert.equal((await rawGet('/console/me', { authorization: `Bearer ${rawToken(hCb.location!)}`, cookie: hCb.cookie }, httpBase)).status, 200);
  } finally {
    httpNode.stop();
  }
});
