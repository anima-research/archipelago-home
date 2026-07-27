import { test } from 'node:test';
import assert from 'node:assert/strict';
import { completeOAuth, displayNameOf } from '../src/oauth.js';

function fakeFetch(routes: Record<string, { status: number; body: unknown }>): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = String(input instanceof Request ? input.url : input);
    for (const [k, v] of Object.entries(routes)) {
      if (url.includes(k)) {
        return new Response(JSON.stringify(v.body), { status: v.status });
      }
    }
    return new Response('not found', { status: 404 });
  }) as typeof fetch;
}

const OPTS = { clientId: 'c', clientSecret: 's', redirectUri: 'https://id.test/oauth/callback', code: 'x', guildId: 'g1' };

test('happy path: user + member roles', async () => {
  const res = await completeOAuth(OPTS, fakeFetch({
    '/oauth2/token': { status: 200, body: { access_token: 't', token_type: 'Bearer' } },
    '/users/@me/guilds/g1/member': { status: 200, body: { roles: ['r1', 'r2'], nick: 'antra' } },
    '/users/@me': { status: 200, body: { id: '123', username: 'olena', global_name: 'Olena' } },
  }));
  assert.equal(res.user.id, '123');
  assert.deepEqual(res.member?.roles, ['r1', 'r2']);
  assert.equal(displayNameOf(res.user, res.member), 'antra');
});

test('not in guild → member null, not an error', async () => {
  const res = await completeOAuth(OPTS, fakeFetch({
    '/oauth2/token': { status: 200, body: { access_token: 't' } },
    '/users/@me/guilds/g1/member': { status: 404, body: { message: 'Unknown Guild' } },
    '/users/@me': { status: 200, body: { id: '123', username: 'olena' } },
  }));
  assert.equal(res.member, null);
  assert.equal(displayNameOf(res.user, null), 'olena');
});

test('failed code exchange throws', async () => {
  await assert.rejects(
    completeOAuth(OPTS, fakeFetch({ '/oauth2/token': { status: 400, body: {} } })),
    /token exchange failed/,
  );
});
