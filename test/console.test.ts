import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKey } from '../src/keys.js';
import { verifyToken } from '../src/token.js';
import { makeEnrollRequest } from '../src/statements.js';
import { handleEnroll, type ExchangeDeps } from '../src/exchange.js';
import { InviteStore, MintLog, PrincipalStore } from '../src/stores.js';
import {
  activeSponsorInvites, delegableScopes, inviteAudiences, mintSponsoredInvite, residentScopes, sponsorInviteView,
} from '../src/console.js';

const SPONSOR = { sub: 'human:discord:111', name: 'antra', scopes: ['worlds:join', 'worlds:spectate', 'orrery:use'] };
const RESIDENT = ['board:read', 'board:write', 'clawblox:play', 'docs:use', 'music:scribe',
  'music:upload', 'orrery:use', 'worlds:join', 'worlds:spectate'];
const KNOWN = ['board', 'body', 'canon', 'clawblox-mesa', 'docs', 'eidoverse', 'eidoverse2', 'gate', 'music', 'orrery'];


let dir: string;
let invites: InviteStore;
let principals: PrincipalStore;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'console-'));
  invites = new InviteStore(join(dir, 'invites.json'));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({ principals: [] }));
  principals = new PrincipalStore(join(dir, 'principals.json'));
});

test('delegation never exceeds the sponsor', () => {
  assert.deepEqual(delegableScopes(SPONSOR.scopes), ['worlds:join', 'worlds:spectate', 'orrery:use']);
  assert.deepEqual(delegableScopes(['worlds:join', 'admin:everything']), ['worlds:join']);
  assert.deepEqual(delegableScopes(['orrery:use']), ['orrery:use']);
  // music scopes delegate like any other held scope (antra 08-17: scribe-holders
  // pass scribe down — Lari's agents)
  assert.deepEqual(delegableScopes(['worlds:join', 'music:upload', 'music:scribe']),
    ['worlds:join', 'music:upload', 'music:scribe']);
  assert.deepEqual(delegableScopes(['worlds:join', 'music:upload']), ['worlds:join', 'music:upload']);

  const r = mintSponsoredInvite(invites, SPONSOR, 'helper');
  assert.ok(r.ok);
  assert.deepEqual(r.invite.scopes, ['worlds:join', 'worlds:spectate', 'orrery:use']);
  assert.deepEqual(r.invite.audiences, ['eidoverse', 'orrery']);
  assert.equal(r.invite.sponsor, SPONSOR.sub);
  assert.equal(r.invite.maxUses, 1);
  assert.equal((r.invite.claims as { sponsor?: string }).sponsor, SPONSOR.sub);

  // spectate-only sponsor: no worlds:join → refused outright
  const weak = mintSponsoredInvite(invites, { ...SPONSOR, scopes: ['worlds:spectate'] }, undefined);
  assert.ok(!weak.ok && weak.status === 403);
});

test('budget: three active invites, then 429; claims free the slot', () => {
  for (let i = 0; i < 3; i++) assert.ok(mintSponsoredInvite(invites, SPONSOR, `a${i}`).ok);
  const fourth = mintSponsoredInvite(invites, SPONSOR, 'a3');
  assert.ok(!fourth.ok && fourth.status === 429);
  assert.equal(activeSponsorInvites(invites, SPONSOR.sub).length, 3);

  // a claim consumes a slot
  invites.consume(invites.all()[0]!.code);
  assert.ok(mintSponsoredInvite(invites, SPONSOR, 'again').ok);

  // other sponsors have their own budget
  assert.ok(mintSponsoredInvite(invites, { ...SPONSOR, sub: 'human:discord:222', name: 'lari' }, undefined).ok);
});

test('id:anchor sponsors grant music scopes outright, with the music audience', () => {
  const admin = { ...SPONSOR, scopes: [...SPONSOR.scopes, 'id:anchor'] };
  // granted even though the admin holds neither music scope personally
  assert.deepEqual(delegableScopes(admin.scopes).sort(),
    ['music:scribe', 'music:upload', 'orrery:use', 'worlds:join', 'worlds:spectate']);
  const r = mintSponsoredInvite(invites, admin, 'house scribe');
  assert.ok(r.ok);
  assert.ok(r.invite.scopes.includes('music:upload') && r.invite.scopes.includes('music:scribe'));
  assert.deepEqual(r.invite.audiences, ['eidoverse', 'orrery', 'music']);
  // a music:upload-holding non-admin gets the audience too, but never scribe
  const uploader = { ...SPONSOR, scopes: ['worlds:join', 'music:upload'] };
  const u = mintSponsoredInvite(invites, { ...uploader, sub: 'human:discord:333' }, undefined);
  assert.ok(u.ok);
  assert.deepEqual(u.invite.scopes, ['worlds:join', 'music:upload']);
  assert.deepEqual(u.invite.audiences, ['eidoverse', 'music']);
});

test('anchoring requires the id:anchor grant and stamps domain + resident tier', () => {
  // without the grant: refused even for a worlds:join holder
  const plain = mintSponsoredInvite(invites, SPONSOR, 'x', { anchorDomain: 'id.test' });
  assert.ok(!plain.ok && plain.status === 403);
  assert.match((plain as { error: string }).error, /id:anchor/);

  const anchor = { ...SPONSOR, scopes: [...SPONSOR.scopes, 'id:anchor'] };
  const r = mintSponsoredInvite(invites, anchor, 'resident agent', { anchorDomain: 'id.test' });
  assert.ok(r.ok);
  assert.equal(r.invite.domain, 'id.test');
  assert.equal((r.invite.claims as { tier?: string }).tier, 'resident');
  assert.deepEqual([...r.invite.scopes].sort(), RESIDENT);
  // un-anchored mint from the same sponsor stays @guest-tier
  const g = mintSponsoredInvite(invites, anchor, 'guest agent');
  assert.ok(g.ok);
  assert.equal(g.invite.domain, undefined);
  assert.equal((g.invite.claims as { tier?: string }).tier, 'sponsored');
});

test('docs + clawblox delegate like any held scope, with their audiences; board never does', () => {
  // a team member's login scopes (as on the live role map)
  const team = {
    sub: 'human:discord:444', name: 'tel', scopes: ['board:read', 'board:team', 'clawblox:play', 'docs:use',
      'gate:admin', 'gate:buy', 'orrery:use', 'worlds:join', 'worlds:spectate', 'music:scribe', 'music:upload'],
  };
  const r = mintSponsoredInvite(invites, team, 'guest helper', { knownAudiences: KNOWN });
  assert.ok(r.ok);
  assert.deepEqual([...r.invite.scopes].sort(),
    ['clawblox:play', 'docs:use', 'music:scribe', 'music:upload', 'orrery:use', 'worlds:join', 'worlds:spectate']);
  assert.ok(!r.invite.scopes.some((s) => s.startsWith('board:') || s.startsWith('gate:')));
  assert.deepEqual(r.invite.audiences, ['eidoverse', 'orrery', 'music', 'docs', 'clawblox-mesa']);
  assert.equal(r.invite.domain, undefined);

  // a sponsor without docs/clawblox can't pass them (∩ still holds)
  const evt = mintSponsoredInvite(invites, { ...SPONSOR, sub: 'human:discord:555' }, undefined, { knownAudiences: KNOWN });
  assert.ok(evt.ok);
  assert.ok(!evt.invite.scopes.includes('docs:use') && !evt.invite.scopes.includes('clawblox:play'));
  assert.deepEqual(evt.invite.audiences, ['eidoverse', 'orrery']);

  // clawblox audiences are per-world: every registered clawblox-* joins
  assert.deepEqual(inviteAudiences(['worlds:join', 'clawblox:play'], false, ['clawblox-z', 'eidoverse', 'clawblox-a']),
    ['eidoverse', 'clawblox-a', 'clawblox-z']);
});

test('an anchored invite carries the full resident grant, whatever the sponsor holds', () => {
  assert.deepEqual([...residentScopes()].sort(), RESIDENT);
  // anchor holder who personally lacks board:write / music / docs / clawblox
  const anchor = { ...SPONSOR, scopes: ['worlds:join', 'worlds:spectate', 'id:anchor'] };
  const r = mintSponsoredInvite(invites, anchor, 'resident', { anchorDomain: 'id.test', knownAudiences: KNOWN });
  assert.ok(r.ok);
  assert.deepEqual([...r.invite.scopes].sort(), RESIDENT);
  // eidoverse first: enrollment's token is for audiences[0]
  assert.deepEqual(r.invite.audiences, ['eidoverse', 'board', 'body', 'canon', 'clawblox-mesa', 'docs', 'music', 'orrery']);
  assert.equal(r.invite.tokenTtl, '7d');
  // never LESS than a plain invite: extra delegable scopes the sponsor holds survive
  const builder = { ...anchor, scopes: [...anchor.scopes, 'worlds:build'] };
  const b = mintSponsoredInvite(invites, { ...builder, sub: 'human:discord:666' }, 'r2', { anchorDomain: 'id.test' });
  assert.ok(b.ok);
  assert.ok(b.invite.scopes.includes('worlds:build'));
  // the same sponsor's un-anchored invite gets no board
  const g = mintSponsoredInvite(invites, anchor, 'guest', { knownAudiences: KNOWN });
  assert.ok(g.ok);
  assert.ok(!g.invite.scopes.some((s) => s.startsWith('board:')));
});

test('end-to-end: anchored invite → enroll → resident at the home domain', () => {
  const issuer = generateKey();
  const deps: ExchangeDeps = {
    issuer, iss: 'id.test', principals, invites,
    mintLog: new MintLog(join(dir, 'minted.jsonl')),
    knownAudiences: () => KNOWN,
  };
  const anchor = { ...SPONSOR, scopes: [...SPONSOR.scopes, 'id:anchor'] };
  const minted = mintSponsoredInvite(invites, anchor, 'sona', { anchorDomain: 'id.test', knownAudiences: KNOWN });
  assert.ok(minted.ok);
  const agentKey = generateKey();
  const res = handleEnroll(makeEnrollRequest(agentKey.privateKey, agentKey.id, 'id.test', minted.invite.code, 'Sona'), deps);
  assert.equal(res.status, 200);
  // the token handed back at enrollment is one the agent can use straight away
  const tok = verifyToken((res.body as { token: string }).token, { issuerId: issuer.id, iss: 'id.test', aud: 'eidoverse' });
  assert.ok(tok.ok, !tok.ok ? tok.reason : '');
  const p = principals.bySub('agent:sona@id.test')!;
  assert.ok(p);
  assert.deepEqual([...p.scopes].sort(), RESIDENT);
  assert.ok(p.audiences!.includes('board') && p.audiences!.includes('clawblox-mesa'));
  assert.equal((p.claims as { tier?: string }).tier, 'resident');
  assert.equal(p.tokenTtl, '7d');
});

test('end-to-end: sponsored invite → enroll → principal carries the vouch', async () => {
  const issuer = generateKey();
  const deps: ExchangeDeps = {
    issuer, iss: 'id.test', principals, invites,
    mintLog: new MintLog(join(dir, 'minted.jsonl')),
    knownAudiences: () => ['eidoverse', 'orrery'],
  };
  const minted = mintSponsoredInvite(invites, SPONSOR, "skye's agent");
  assert.ok(minted.ok);

  const agentKey = generateKey();
  const req = makeEnrollRequest(agentKey.privateKey, agentKey.id, 'id.test', minted.invite.code, 'Wisp');
  const res = handleEnroll(req, deps);
  assert.equal(res.status, 200);
  const { sub, token } = res.body as { sub: string; token: string };
  assert.equal(sub, 'agent:wisp@guest');

  // the vouch travels: principal claims → every future token
  const p = principals.bySub(sub)!;
  assert.equal((p.claims as { sponsor?: string }).sponsor, SPONSOR.sub);
  assert.equal((p.claims as { tier?: string }).tier, 'sponsored');
  const v = verifyToken(token, { issuerId: issuer.id, iss: 'id.test', aud: 'eidoverse' });
  assert.ok(v.ok);
  assert.equal((v.payload.claims as { sponsorName?: string }).sponsorName, 'antra');

  // sponsor's view shows the claim and the enrolled agent
  const view = sponsorInviteView(invites, principals, SPONSOR.sub);
  assert.equal(view.length, 1);
  assert.equal(view[0]!.status, 'claimed');
  assert.deepEqual(view[0]!.agent, { sub: 'agent:wisp@guest', name: 'Wisp' });
});
