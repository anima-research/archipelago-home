/**
 * One person, one account (src/same-person.ts): the same address on Discord
 * and Google joins them, a Google account the node has never seen is asked
 * first, and `hn user merge` folds two accounts that already exist.
 *
 * End to end over HTTP against a real HomeNode with Discord (bot-token role
 * lookup) and Google faked at the fetch seam; the CLI is the real one,
 * spawned against the node's data dir.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HomeNode } from '../src/server.js';
import { verifyToken, type Aid1Payload } from '../src/token.js';
import { hashPassword, type HumanAccount } from '../src/accounts.js';
import { addressHash, mergeAccounts, sameAddress } from '../src/same-person.js';

const ROOT = join(import.meta.dirname, '..');
const ORIGIN = 'https://id.test';
let node: HomeNode;
let base: string;
let dir: string;
let ipSeq = 0;

// Discord as the fake sees it: who the next OAuth returns, and what the guild says about each id.
type Dc = { id: string; username: string; global_name?: string; email?: string | null; verified?: boolean };
let discordUser: Dc = { id: '100000000000000001', username: 'nobody' };
const guild = new Map<string, { roles: string[]; user: Dc }>();
let googleUser: Record<string, unknown> = {};
const b64j = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');

/** The next Discord sign-in is this person, in the guild with these roles (null = not in it). */
function discord(u: Dc, roles: string[] | null = ['r-member']): void {
  discordUser = u;
  if (roles) guild.set(u.id, { roles, user: u });
  else guild.delete(u.id);
}

const fakeFetch = (async (input: string | URL | Request) => {
  const url = String(input);
  const ok = (body: unknown) => new Response(JSON.stringify(body), { status: 200 });
  if (url === 'https://oauth2.googleapis.com/token') {
    const claims = { iss: 'https://accounts.google.com', aud: 'gcid', exp: Math.floor(Date.now() / 1000) + 300, ...googleUser };
    return ok({ id_token: `${b64j({ alg: 'RS256' })}.${b64j(claims)}.sig` });
  }
  if (url.endsWith('/oauth2/token')) return ok({ access_token: 't', token_type: 'Bearer' });
  if (url.endsWith('/users/@me')) return ok(discordUser);
  const m = /\/guilds\/g1\/members\/(\d+)$/.exec(url);
  if (m) {
    const e = guild.get(m[1]!);
    return e ? ok({ roles: e.roles, nick: null, user: e.user }) : new Response('{}', { status: 404 });
  }
  return new Response('nope', { status: 500 });
}) as typeof fetch;

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'hn-same-'));
  writeFileSync(join(dir, 'roles.json'), JSON.stringify({
    guildId: 'g1',
    map: { 'r-member': { scopes: ['worlds:join'] }, 'r-team': { scopes: ['worlds:join', 'id:anchor'] } },
  }));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({ principals: [] }));
  copyFileSync(join(ROOT, 'config', 'invite-policy.example.json'), join(dir, 'invite-policy.json'));
  writeFileSync(join(dir, 'audiences.json'), JSON.stringify({
    eidoverse: { redirect: 'https://worlds.test/auth', requiredScopes: ['worlds:join'] },
    notes: { redirect: 'https://notes.test/auth', requiredScopes: ['notes:use'], signup: {} }, // open to newcomers
  }));
  node = new HomeNode({
    iss: 'id.test', publicUrl: ORIGIN, bind: '127.0.0.1', port: 0, dataDir: dir, configDir: dir,
    discordClientId: 'cid', discordClientSecret: 'secret', discordBotToken: 'bot', googleClientId: 'gcid', googleClientSecret: 'gsecret',
  }, { fetchImpl: fakeFetch });
  base = `http://127.0.0.1:${await node.start()}`;
});
after(() => node.stop());

// Each request from its own address so the per-IP limiter stays out of the way.
const hdrs = (extra: Record<string, string> = {}) => ({ 'x-real-ip': `10.1.${ipSeq >> 8 & 255}.${ipSeq++ & 255}`, ...extra });
const cookiesOf = (h: Headers) => h.getSetCookie().map((c) => c.split(';')[0]!).join('; ');

async function get(path: string, cookie = '') {
  const r = await fetch(base + path, { headers: hdrs(cookie ? { cookie } : {}), redirect: 'manual' });
  return { status: r.status, text: await r.text(), location: r.headers.get('location'), cookies: cookiesOf(r.headers) };
}
async function post(path: string, body: unknown, cookie = '') {
  const r = await fetch(base + path, { method: 'POST', body: JSON.stringify(body), headers: hdrs({ 'content-type': 'application/json', ...(cookie ? { cookie } : {}) }) });
  return { status: r.status, body: (await r.json()) as Record<string, any>, cookies: cookiesOf(r.headers) };
}
function tokenFrom(redirect: string, aud: string): Aid1Payload {
  const v = verifyToken(/#token=(.+)$/.exec(redirect)![1]!, { issuerId: node.issuer.id, iss: 'id.test', aud });
  assert.ok(v.ok, !v.ok ? v.reason : '');
  return v.payload;
}
async function discordLogin(audience: string) {
  const start = await get(`/login?audience=${audience}&via=discord`);
  assert.match(new URL(start.location!).searchParams.get('scope')!, /\bemail\b/); // what the address is asked with
  return get(`/oauth/callback?state=${new URL(start.location!).searchParams.get('state')}&code=x`);
}
const both = (...c: string[]) => c.filter(Boolean).join('; ');
/** The Google callback as the browser that started the sign-in gets it (it sends back the cookie
 *  /login gave it): a redirect, a refusal, or the first-time page (its `id`). `browser` is that cookie. */
async function googleLogin(audience: string, cookie = '') {
  const start = await get(`/login?audience=${audience}&via=google`, cookie);
  const browser = start.cookies;
  assert.match(browser, /^__Host-hn_browser=[A-Za-z0-9_-]{32}$/);
  const r = await get(`/oauth/google/callback?state=${new URL(start.location!).searchParams.get('state')}&code=x`, both(cookie, browser));
  return { ...r, browser, id: r.status === 200 ? /const S = \{"id":"([^"]+)"\}/.exec(r.text)?.[1] : undefined };
}
const hn = (...args: string[]) => {
  const r = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', 'user', ...args], {
    cwd: ROOT, encoding: 'utf8', env: { ...process.env, HN_DATA_DIR: dir, HN_CONFIG_DIR: dir, HN_DOMAIN: 'id.test' },
  });
  return { status: r.status, out: `${r.stdout}${r.stderr}` };
};

// ── 1. the same address on both sides ──

test('same address: a Google account arriving after its Discord account joins it — no second account, no page', async () => {
  discord({ id: '100000000000000011', username: 'dana', global_name: 'Dana', email: 'dana.q@gmail.com', verified: true });
  const d = await discordLogin('eidoverse');
  assert.equal(tokenFrom(d.location!, 'eidoverse').sub, 'human:discord:100000000000000011');
  assert.equal(node.accounts.byDiscord('100000000000000011'), undefined); // a Discord person still needs no row
  // the address is remembered as a hash, never itself
  const kept = readFileSync(join(dir, 'discord-addresses.json'), 'utf8');
  assert.doesNotMatch(kept, /dana/);
  assert.equal(JSON.parse(kept).addresses['100000000000000011'].hash, addressHash('danaq@gmail.com'));

  // the same mailbox as Gmail delivers it (dots, +suffix), from Google
  googleUser = { sub: 'g-dana', email: 'danaq+home@gmail.com', email_verified: true, name: 'Dana Q' };
  const g = await googleLogin('eidoverse');
  assert.equal(g.status, 302, g.text);
  const p = tokenFrom(g.location!, 'eidoverse');
  assert.equal(p.sub, 'human:discord:100000000000000011');
  assert.deepEqual(p.scopes, ['worlds:join']); // the Discord roles, read live
  assert.equal(p.name, 'Dana');
  const row = node.accounts.bySub('human:discord:100000000000000011')!;
  assert.equal(row.google?.sub, 'g-dana');
  assert.equal(node.accounts.bySub('human:google:g-dana'), undefined);
  // and from then on Google opens it by its own id, whatever its address becomes
  googleUser = { sub: 'g-dana', email: 'someoneelse@example.org', email_verified: true };
  assert.equal(tokenFrom((await googleLogin('eidoverse')).location!, 'eidoverse').sub, 'human:discord:100000000000000011');
});

test('same address: a Discord account nobody has used here joins the account its Google address made', async () => {
  googleUser = { sub: 'g-eve', email: 'eve@gmail.com', email_verified: true, name: 'Eve' };
  const first = await googleLogin('notes');
  assert.ok(first.id, 'a Google account never seen is asked first');
  const made = await post('/login/new', { id: first.id, as: 'new' });
  assert.equal(tokenFrom(made.body.redirect, 'notes').sub, 'human:google:g-eve');

  discord({ id: '100000000000000012', username: 'eve_dc', global_name: 'Eve D', email: 'Eve@gmail.com', verified: true });
  const d = await discordLogin('eidoverse');
  assert.equal(d.status, 302, d.text);
  const p = tokenFrom(d.location!, 'eidoverse');
  assert.equal(p.sub, 'human:google:g-eve'); // the account that was there keeps its id
  assert.deepEqual(p.scopes, ['worlds:join']); // and Discord's roles now add to it
  assert.equal(node.accounts.bySub('human:google:g-eve')!.discord?.id, '100000000000000012');
  assert.ok(d.cookies.includes('hn_session=')); // it has a row now: a session to continue as
});

test('same address: never joined on an address only one side vouches for', async () => {
  // Discord hasn't verified it: nothing is remembered, so Google with that address is a newcomer
  discord({ id: '100000000000000013', username: 'ugo', email: 'ugo@gmail.com', verified: false });
  await discordLogin('eidoverse');
  assert.equal(node.discordAddresses.all()['100000000000000013'], undefined);
  googleUser = { sub: 'g-ugo', email: 'ugo@gmail.com', email_verified: true };
  assert.ok((await googleLogin('eidoverse')).id);
  assert.equal(node.accounts.byDiscord('100000000000000013'), undefined);

  // Google isn't authoritative for it (not Gmail, no Workspace domain): asked, not joined
  discord({ id: '100000000000000014', username: 'vic', email: 'vic@corp.example', verified: true });
  await discordLogin('eidoverse');
  googleUser = { sub: 'g-vic', email: 'vic@corp.example', email_verified: true };
  assert.ok((await googleLogin('eidoverse')).id);
  assert.equal(node.accounts.byDiscord('100000000000000014'), undefined);
  // a Workspace account for that domain IS vouched for
  googleUser = { sub: 'g-vic', email: 'vic@corp.example', email_verified: true, hd: 'corp.example' };
  assert.equal(tokenFrom((await googleLogin('eidoverse')).location!, 'eidoverse').sub, 'human:discord:100000000000000014');

  // an address Discord stops vouching for is forgotten
  discord({ id: '100000000000000014', username: 'vic', email: null });
  await discordLogin('eidoverse');
  assert.equal(node.discordAddresses.all()['100000000000000014'], undefined);
});

test('same address: by hand only for the node’s own powers and for restricted people', async () => {
  // id:anchor by role: Google with the same address is asked, never joined
  discord({ id: '100000000000000015', username: 'tess', email: 'tess@gmail.com', verified: true }, ['r-team']);
  await discordLogin('eidoverse');
  googleUser = { sub: 'g-tess', email: 'tess@gmail.com', email_verified: true };
  assert.ok((await googleLogin('eidoverse')).id);
  assert.equal(node.accounts.byDiscord('100000000000000015'), undefined);

  // hn:admin on the row
  discord({ id: '100000000000000016', username: 'adam', email: 'adam@gmail.com', verified: true });
  node.accounts.add({ sub: 'human:discord:100000000000000016', discord: { id: '100000000000000016' }, scopes: ['hn:admin'], createdAt: new Date().toISOString() });
  await discordLogin('eidoverse');
  googleUser = { sub: 'g-adam', email: 'adam@gmail.com', email_verified: true };
  assert.ok((await googleLogin('eidoverse')).id);
  assert.equal(node.accounts.bySub('human:discord:100000000000000016')!.google, undefined);

  // operator restrictions on the row
  discord({ id: '100000000000000017', username: 'rex', email: 'rex@gmail.com', verified: true });
  node.accounts.add({ sub: 'human:discord:100000000000000017', discord: { id: '100000000000000017' }, withhold: ['id:anchor'], createdAt: new Date().toISOString() });
  await discordLogin('eidoverse');
  googleUser = { sub: 'g-rex', email: 'rex@gmail.com', email_verified: true };
  assert.ok((await googleLogin('eidoverse')).id);
  assert.equal(node.accounts.bySub('human:discord:100000000000000017')!.google, undefined);

  // the other direction: a team member's Discord never lands on a Google account by itself
  googleUser = { sub: 'g-tom', email: 'tom@gmail.com', email_verified: true };
  await post('/login/new', { id: (await googleLogin('notes')).id, as: 'new' });
  discord({ id: '100000000000000018', username: 'tom', email: 'tom@gmail.com', verified: true }, ['r-team']);
  assert.equal(tokenFrom((await discordLogin('eidoverse')).location!, 'eidoverse').sub, 'human:discord:100000000000000018');
  assert.equal(node.accounts.bySub('human:google:g-tom')!.discord, undefined);
  // …but the operator is shown the pair
  assert.ok(sameAddress(node.accounts.all(), node.discordAddresses.all()).some((p) => p.discordId === '100000000000000018' && p.google.sub === 'human:google:g-tom'));
});

// ── 2. different addresses: asked first ──

test('first time: nothing is made until they answer; "I’ve signed in here with Discord" joins the two', async () => {
  discord({ id: '100000000000000021', username: 'gus', global_name: 'Gus', email: 'gus@proton.example', verified: true });
  await discordLogin('eidoverse'); // a Discord person, known here by another address

  googleUser = { sub: 'g-gus', email: 'gus.other@gmail.com', email_verified: true, name: 'Gus G' };
  const first = await googleLogin('eidoverse');
  assert.equal(first.status, 200);
  assert.match(first.text, /<b>gus\.other@gmail\.com<\/b> hasn’t signed in here before/);
  assert.match(first.text, /I’ve signed in here with Discord/);
  assert.match(first.text, /I’m new here/);
  assert.doesNotMatch(first.text, /Add this Google account to/); // no session in this browser
  assert.equal(node.accounts.byGoogle('g-gus'), undefined);

  const hop = await post('/login/new', { id: first.id, as: 'discord' }, first.browser);
  assert.equal(hop.status, 200, JSON.stringify(hop.body));
  assert.equal(hop.cookies, first.browser); // the same value, renewed for the trip to Discord
  assert.match(hop.body.redirect, /^https:\/\/id\.test\/login\/discord\?state=/);
  const state = new URL(hop.body.redirect).searchParams.get('state')!;
  // the page's answer is spent
  assert.equal((await post('/login/new', { id: first.id, as: 'new' })).status, 400);

  // another browser can't finish it: someone handed the link would attach THEIR Discord to this Google account
  const other = await googleLogin('eidoverse');
  const stranger = await post('/login/new', { id: other.id, as: 'discord' }, other.browser);
  const strangerBack = `/oauth/callback?state=${new URL(stranger.body.redirect).searchParams.get('state')}&code=x`;
  assert.equal((await get(strangerBack, '__Host-hn_browser=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')).status, 403);
  assert.equal((await get(strangerBack, stranger.cookies)).status, 400); // and the state was spent by the try
  assert.equal(node.accounts.byGoogle('g-gus'), undefined);

  const back = await get(`/oauth/callback?state=${state}&code=x`, hop.cookies);
  assert.equal(back.status, 302, back.text);
  const p = tokenFrom(back.location!, 'eidoverse');
  assert.equal(p.sub, 'human:discord:100000000000000021');
  assert.deepEqual(p.scopes, ['worlds:join']);
  assert.equal(node.accounts.bySub('human:discord:100000000000000021')!.google?.sub, 'g-gus');
  assert.equal(node.accounts.bySub('human:google:g-gus'), undefined);
  // Google signs in to it from now on, with no page
  assert.equal(tokenFrom((await googleLogin('eidoverse')).location!, 'eidoverse').sub, 'human:discord:100000000000000021');

  // a second Google account can't take the same road: the account has one
  googleUser = { sub: 'g-gus-2', email: 'gus.second@gmail.com', email_verified: true };
  const second = await googleLogin('eidoverse');
  const again = await post('/login/new', { id: second.id, as: 'discord' }, second.browser);
  const refused = await get(`/oauth/callback?state=${new URL(again.body.redirect).searchParams.get('state')}&code=x`, again.cookies);
  assert.equal(refused.status, 409);
  assert.match(refused.text, /already has a Google account/);
  assert.equal(node.accounts.byGoogle('g-gus-2'), undefined);
});

test('first time: signed in here already — "Add this Google account to …" puts it on that account', async () => {
  node.accounts.add({ sub: 'human:local:lena', username: 'lena', password: await hashPassword('lena password 1'), scopes: ['worlds:join'], createdAt: new Date().toISOString() });
  const page = await get('/login?audience=eidoverse');
  const signedIn = await post('/login/password', { state: /"state":"([^"]+)"/.exec(page.text)![1], username: 'lena', password: 'lena password 1' });
  assert.equal(signedIn.status, 200);
  const session = signedIn.cookies;
  assert.match(session, /hn_session=/);

  googleUser = { sub: 'g-lena', email: 'lena@gmail.com', email_verified: true };
  const first = await googleLogin('eidoverse', session);
  assert.match(first.text, /Add this Google account to lena/);
  // the answer counts only with that session
  assert.equal((await post('/login/new', { id: (await googleLogin('eidoverse', session)).id, as: 'session' })).status, 400);
  assert.equal(node.accounts.byGoogle('g-lena'), undefined);
  const r = await post('/login/new', { id: first.id, as: 'session' }, session);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(tokenFrom(r.body.redirect, 'eidoverse').sub, 'human:local:lena');
  assert.equal(node.accounts.bySub('human:local:lena')!.google?.sub, 'g-lena');
});

test('first time: a Google return opened in another browser is never asked — nothing of the sender’s lands on the person looking', async () => {
  // someone signed in here, with a session in their browser
  node.accounts.add({ sub: 'human:local:vera', username: 'vera', password: await hashPassword('vera password 1'), scopes: ['worlds:join', 'hn:admin'], createdAt: new Date().toISOString() });
  const page = await get('/login?audience=eidoverse');
  const session = (await post('/login/password', { state: /"state":"([^"]+)"/.exec(page.text)![1], username: 'vera', password: 'vera password 1' })).cookies;

  // another person starts a Google sign-in in THEIR browser and hands over the return link
  googleUser = { sub: 'g-mallory', email: 'mallory@gmail.com', email_verified: true };
  const start = await get('/login?audience=notes&via=google');
  const link = `/oauth/google/callback?state=${new URL(start.location!).searchParams.get('state')}&code=x`;
  // opened with vera's session, and with a browser value of her own from a sign-in page she had open
  const hers = (await get('/login?audience=notes')).cookies;
  const r = await get(link, both(session, hers));
  assert.equal(r.status, 302, r.text); // as before this page existed: the sender's own new account, no question asked
  assert.equal(tokenFrom(r.location!, 'notes').sub, 'human:google:g-mallory');
  assert.doesNotMatch(r.text, /Add this Google account/);
  assert.equal(node.accounts.bySub('human:local:vera')!.google, undefined);
  // and with no cookie at all
  googleUser = { sub: 'g-mallory-2', email: 'mallory2@gmail.com', email_verified: true };
  const start2 = await get('/login?audience=notes&via=google');
  const r2 = await get(`/oauth/google/callback?state=${new URL(start2.location!).searchParams.get('state')}&code=x`, session);
  assert.equal(tokenFrom(r2.location!, 'notes').sub, 'human:google:g-mallory-2');
  assert.equal(node.accounts.bySub('human:local:vera')!.google, undefined);
});

test('first time: "I’m new here" at a closed door makes the account and says where it can go', async () => {
  googleUser = { sub: 'g-nia', email: 'nia@gmail.com', email_verified: true };
  const first = await googleLogin('eidoverse');
  assert.match(first.text, /<div id="hint" hidden>.*Open to everyone: <a href="https:\/\/notes\.test">notes\.test<\/a>/s);
  const r = await post('/login/new', { id: first.id, as: 'new' });
  assert.equal(r.status, 403);
  assert.match(r.body.error, /signed in, but no access/);
  assert.ok(node.accounts.bySub('human:google:g-nia'));
});

// ── 3. two accounts already ──

test('two accounts already: a Discord identity used here on its own is listed, not joined — and merged by the operator', async () => {
  // used here as itself while Discord vouched for no address
  discord({ id: '100000000000000031', username: 'fay', global_name: 'Fay', email: 'fay@gmail.com', verified: false });
  await discordLogin('eidoverse');
  // their Google account, with nothing to match on, became an account of its own, redeeming a code on the way
  const { code, record } = node.codes.add({ label: 'notes', audiences: ['notes'], scopes: ['notes:use'] });
  googleUser = { sub: 'g-fay', email: 'fay@gmail.com', email_verified: true, name: 'Fay G' };
  const pg = await get('/login?audience=notes');
  const st = /"state":"([^"]+)"/.exec(pg.text)![1]!;
  await post('/login/code', { state: st, code });
  const viaG = await get(`/login/google?state=${st}`, pg.cookies);
  const cb = await get(`/oauth/google/callback?state=${new URL(viaG.location!).searchParams.get('state')}&code=x`, pg.cookies);
  await post('/login/new', { id: /const S = \{"id":"([^"]+)"\}/.exec(cb.text)![1], as: 'new' });
  const g = node.accounts.bySub('human:google:g-fay')!;
  assert.deepEqual(g.codes?.map((c) => c.id), [record.id]);
  // the Google account sponsors an agent and has an invite out
  node.principals.add({ sub: 'agent:fays-agent@guest', name: 'FaysAgent', kind: 'agent', key: null, scopes: [], claims: { sponsor: 'human:google:g-fay', sponsorName: 'Fay G' } });
  node.invites.mint({ code: 'inv_fay', scopes: [], sponsor: 'human:google:g-fay', claims: { sponsor: 'human:google:g-fay' } });

  // Discord now vouches for the address — too late to join by itself: both have been someone here
  discord({ id: '100000000000000031', username: 'fay', global_name: 'Fay', email: 'fay@gmail.com', verified: true });
  assert.equal(tokenFrom((await discordLogin('eidoverse')).location!, 'eidoverse').sub, 'human:discord:100000000000000031');
  assert.equal(node.accounts.bySub('human:google:g-fay')!.discord, undefined);
  assert.ok(sameAddress(node.accounts.all(), node.discordAddresses.all()).some((p) => p.discordId === '100000000000000031' && p.google.sub === 'human:google:g-fay'));

  const dupes = hn('dupes');
  assert.equal(dupes.status, 0, dupes.out);
  assert.match(dupes.out, /human:discord:100000000000000031 \(no row: Discord only\)\s+and\s+human:google:g-fay/);

  // without --yes: what would happen, and nothing does
  const show = hn('merge', 'human:google:g-fay', '100000000000000031');
  assert.equal(show.status, 0, show.out);
  assert.match(show.out, /signed in to: notes ×1/);
  assert.match(show.out, /signed in to: eidoverse ×2/);
  assert.match(show.out, /1 agent\(s\) and 1 invite\(s\) sponsored by human:google:g-fay pass to human:discord:100000000000000031/);
  assert.match(show.out, /nothing changed/);
  assert.ok(node.accounts.bySub('human:google:g-fay'));

  const done = hn('merge', 'human:google:g-fay', '100000000000000031', '--yes');
  assert.equal(done.status, 0, done.out);
  assert.equal(node.accounts.bySub('human:google:g-fay'), undefined);
  const one = node.accounts.bySub('human:discord:100000000000000031')!;
  assert.equal(one.google?.sub, 'g-fay');
  assert.equal(one.discord?.id, '100000000000000031');
  assert.deepEqual(one.was, ['human:google:g-fay']);
  assert.deepEqual(one.codes?.map((c) => c.id), [record.id]);
  const fresh = <T>(file: string) => JSON.parse(readFileSync(join(dir, file), 'utf8')) as T;
  assert.equal(fresh<{ principals: Array<{ sub: string; claims: Record<string, string> }> }>('principals.json').principals.find((p) => p.sub === 'agent:fays-agent@guest')!.claims.sponsor, 'human:discord:100000000000000031');
  const inv = fresh<{ invites: Array<{ code: string; sponsor: string; claims: Record<string, string> }> }>('invites.json').invites.find((i) => i.code === 'inv_fay')!;
  assert.deepEqual([inv.sponsor, inv.claims.sponsor], ['human:discord:100000000000000031', 'human:discord:100000000000000031']);
  assert.deepEqual(fresh<{ codes: Array<{ redeemed: Array<{ sub: string }> }> }>('codes.json').codes[0]!.redeemed.map((r) => r.sub), ['human:discord:100000000000000031']);

  // both ways in now open the one account — with the code's access and Discord's roles
  const viaGoogle = await googleLogin('notes');
  assert.equal(viaGoogle.status, 302, viaGoogle.text);
  assert.equal(tokenFrom(viaGoogle.location!, 'notes').sub, 'human:discord:100000000000000031');
  assert.equal(tokenFrom((await discordLogin('eidoverse')).location!, 'eidoverse').sub, 'human:discord:100000000000000031');
  assert.doesNotMatch(hn('dupes').out, /g-fay/);
});

test('dupes: says so when there is nothing to see', () => {
  const empty = mkdtempSync(join(tmpdir(), 'hn-same-empty-'));
  const r = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', 'user', 'dupes'], { cwd: ROOT, encoding: 'utf8', env: { ...process.env, HN_DATA_DIR: empty, HN_CONFIG_DIR: empty } });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /no two accounts here share an address/);
});

test('merge: refuses what would be a guess, and a typo', () => {
  const now = new Date().toISOString();
  node.accounts.add({ sub: 'human:google:g-m1', google: { sub: 'g-m1', email: 'm1@gmail.com', verified: true }, createdAt: now });
  node.accounts.add({ sub: 'human:google:g-m2', google: { sub: 'g-m2', email: 'm2@gmail.com', verified: true }, createdAt: now });
  const both = hn('merge', 'human:google:g-m1', 'human:google:g-m2', '--yes');
  assert.equal(both.status, 1);
  assert.match(both.out, /both sign in with a Google account/);
  assert.ok(node.accounts.bySub('human:google:g-m1'));
  // a Discord id nobody has signed in with: no row is conjured for it
  const typo = hn('merge', 'human:google:g-m1', '199999999999999999', '--yes');
  assert.equal(typo.status, 1);
  assert.match(typo.out, /nobody has signed in here as human:discord:199999999999999999/);
  assert.ok(node.accounts.bySub('human:google:g-m1'));
  assert.equal(hn('merge', 'human:google:g-m1', 'human:google:g-m1').status, 1);
});

test('mergeAccounts: restrictions add up, ways in move, and what can’t move is named', () => {
  const at = '2026-11-01T00:00:00Z';
  const from: HumanAccount = {
    sub: 'human:local:old', username: 'old', password: 'scrypt$x', totp: { secret: 's', enabledAt: at }, recovery: ['r'],
    passkeys: [{ id: 'pk1', jwk: {}, alg: -7, signCount: 0, name: 'key', createdAt: at }], webauthnUserId: 'wa-old',
    google: { sub: 'g-old', email: 'old@gmail.com', verified: true }, scopes: ['a:use'], withhold: ['x:admin'], ignoreRoles: ['111111111111111111'],
    claims: { tier: 'old', extra: 1 }, was: ['human:google:earlier'], createdAt: at,
  };
  const into: HumanAccount = {
    sub: 'human:discord:5', discord: { id: '5', name: 'Five' }, google: { email: 'invited@gmail.com' }, scopes: ['b:use'], withhold: ['y:admin'],
    claims: { tier: 'kept' }, notes: 'row made by hand', createdAt: at,
  };
  const m = mergeAccounts(from, into, '2026-11-26');
  assert.ok(typeof m !== 'string');
  const n = m.next;
  assert.equal(n.sub, 'human:discord:5');
  assert.deepEqual([n.username, n.password, n.totp?.secret, n.recovery], ['old', 'scrypt$x', 's', ['r']]);
  assert.deepEqual([n.passkeys?.[0]?.id, n.webauthnUserId], ['pk1', 'wa-old']); // a passkey answers to the handle it was made under
  assert.equal(n.google?.sub, 'g-old');
  assert.deepEqual(n.scopes, ['b:use', 'a:use']);
  assert.deepEqual(n.withhold, ['y:admin', 'x:admin']);
  assert.deepEqual(n.ignoreRoles, ['111111111111111111']);
  // roles are set aside now: the Discord snapshot taken without that doesn't count until a fresh check
  const snap = mergeAccounts(from, { ...into, discord: { id: '5', name: 'Five', grant: { scopes: ['id:anchor'] }, checkedAt: at } }, '2026-11-26');
  assert.ok(typeof snap !== 'string');
  assert.deepEqual(snap.next.discord, { id: '5', name: 'Five' });
  assert.deepEqual(n.claims, { tier: 'kept', extra: 1 });
  assert.deepEqual(n.was, ['human:local:old', 'human:google:earlier']);
  assert.equal(n.notes, 'row made by hand; merged human:local:old 2026-11-26');
  assert.deepEqual(m.left, ['human:discord:5\'s unused Google invitation (invited@gmail.com)']);

  // where the one that stays has its own password and passkeys, the other's are named, not mixed in
  const own: HumanAccount = { ...into, username: 'five', password: 'scrypt$y', passkeys: [{ id: 'pk2', jwk: {}, alg: -7, signCount: 0, name: 'k', createdAt: at }], webauthnUserId: 'wa-five' };
  const m2 = mergeAccounts(from, own, '2026-11-26');
  assert.ok(typeof m2 !== 'string');
  assert.deepEqual([m2.next.username, m2.next.password, m2.next.totp, m2.next.webauthnUserId, m2.next.passkeys?.length], ['five', 'scrypt$y', undefined, 'wa-five', 1]);
  assert.equal(m2.left.length, 3);

  assert.match(mergeAccounts({ ...from, disabled: true }, into, 'd') as string, /disabled/);
  assert.match(mergeAccounts(from, { ...into, discord: undefined, sub: 'human:google:g-x', google: { sub: 'g-x', email: 'x@gmail.com' } }, 'd') as string, /both sign in with a Google account/);
  assert.match(mergeAccounts({ ...from, discord: { id: '6' } }, into, 'd') as string, /both sign in with a Discord account/);
});
