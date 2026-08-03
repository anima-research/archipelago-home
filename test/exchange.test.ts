import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKey } from '../src/keys.js';
import { verifyToken } from '../src/token.js';
import { makeEnrollRequest, makeTokenRequest } from '../src/statements.js';
import { handleEnroll, handleTokenRequest, type ExchangeDeps } from '../src/exchange.js';
import { InviteStore, MintLog, PrincipalStore } from '../src/stores.js';

const issuer = generateKey();
const agentKey = generateKey();
const ISS = 'id.test';

let deps: ExchangeDeps;
let principals: PrincipalStore;
let invites: InviteStore;

beforeEach(() => {
  const dir = mkdtempSync(join(tmpdir(), 'hn-test-'));
  writeFileSync(
    join(dir, 'principals.json'),
    JSON.stringify({
      principals: [
        {
          sub: 'agent:fable@animalabs.ai',
          name: 'Fable',
          kind: 'agent',
          key: agentKey.id,
          scopes: ['worlds:join'],
          tokenTtl: '14d',
        },
      ],
    }),
  );
  principals = new PrincipalStore(join(dir, 'principals.json'));
  invites = new InviteStore(join(dir, 'invites.json'));
  deps = {
    issuer,
    iss: ISS,
    principals,
    invites,
    mintLog: new MintLog(join(dir, 'minted.jsonl')),
    knownAudiences: () => ['eidoverse'],
  };
});

test('key-proof exchange mints a verifiable token', () => {
  const req = makeTokenRequest(agentKey.privateKey, agentKey.id, ISS, 'eidoverse');
  const res = handleTokenRequest(req, deps);
  assert.equal(res.status, 200);
  const v = verifyToken((res.body as { token: string }).token, { issuerId: issuer.id, iss: ISS, aud: 'eidoverse' });
  assert.ok(v.ok);
  assert.equal(v.payload.sub, 'agent:fable@animalabs.ai');
});

test('unenrolled key is refused', () => {
  const stranger = generateKey();
  const req = makeTokenRequest(stranger.privateKey, stranger.id, ISS, 'eidoverse');
  assert.equal(handleTokenRequest(req, deps).status, 403);
});

test('proof from wrong key is refused', () => {
  const stranger = generateKey();
  const req = { ...makeTokenRequest(stranger.privateKey, agentKey.id, ISS, 'eidoverse') };
  assert.equal(handleTokenRequest(req, deps).status, 403);
});

test('stale timestamp is refused', () => {
  const req = makeTokenRequest(agentKey.privateKey, agentKey.id, ISS, 'eidoverse');
  req.timestamp = new Date(Date.now() - 10 * 60_000).toISOString();
  assert.equal(handleTokenRequest(req, deps).status, 400);
});

test('unknown audience is refused', () => {
  const req = makeTokenRequest(agentKey.privateKey, agentKey.id, ISS, 'nether');
  assert.equal(handleTokenRequest(req, deps).status, 400);
});

test('revoked principal is refused', () => {
  principals.revoke('agent:fable@animalabs.ai');
  const req = makeTokenRequest(agentKey.privateKey, agentKey.id, ISS, 'eidoverse');
  assert.equal(handleTokenRequest(req, deps).status, 403);
});

test('enroll: invite + key → new principal + token; invite consumed', () => {
  invites.mint({ code: 'inv_x', scopes: ['worlds:join'], maxUses: 1 });
  const guest = generateKey();
  const req = makeEnrollRequest(guest.privateKey, guest.id, ISS, 'inv_x', 'Ferro');
  const res = handleEnroll(req, deps);
  assert.equal(res.status, 200);
  const body = res.body as { sub: string; token: string };
  assert.equal(body.sub, 'agent:ferro@guest');
  assert.ok(verifyToken(body.token, { issuerId: issuer.id, iss: ISS, aud: 'eidoverse' }).ok);
  assert.ok(principals.byKey(guest.id));
  // second use exhausts
  const guest2 = generateKey();
  const req2 = makeEnrollRequest(guest2.privateKey, guest2.id, ISS, 'inv_x', 'Bolt');
  assert.equal(handleEnroll(req2, deps).status, 403);
});


test('domain-bearing invite anchors the principal at the home domain', () => {
  invites.mint({ code: 'inv_home', scopes: ['worlds:join'], domain: 'animalabs.ai' });
  const guest = generateKey();
  const req = makeEnrollRequest(guest.privateKey, guest.id, ISS, 'inv_home', 'Mythos');
  const res = handleEnroll(req, deps);
  assert.equal(res.status, 200);
  assert.equal((res.body as { sub: string }).sub, 'agent:mythos@animalabs.ai');
});

test('enroll: name collision refused (case-insensitive)', () => {
  invites.mint({ code: 'inv_y', scopes: ['worlds:join'] });
  const guest = generateKey();
  const req = makeEnrollRequest(guest.privateKey, guest.id, ISS, 'inv_y', 'fable');
  const res = handleEnroll(req, deps);
  assert.equal(res.status, 403);
  assert.match((res.body as { error: string }).error, /name taken/);
});

test('enroll: bad invite refused', () => {
  const guest = generateKey();
  const req = makeEnrollRequest(guest.privateKey, guest.id, ISS, 'nope', 'Ferro');
  assert.equal(handleEnroll(req, deps).status, 403);
});
