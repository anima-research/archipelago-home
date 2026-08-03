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
import { activeSponsorInvites, delegableScopes, mintSponsoredInvite, sponsorInviteView } from '../src/console.js';

const SPONSOR = { sub: 'human:discord:111', name: 'antra', scopes: ['worlds:join', 'worlds:spectate', 'orrery:use'] };

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
  // un-anchored mint from the same sponsor stays @guest-tier
  const g = mintSponsoredInvite(invites, anchor, 'guest agent');
  assert.ok(g.ok);
  assert.equal(g.invite.domain, undefined);
  assert.equal((g.invite.claims as { tier?: string }).tier, 'sponsored');
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
