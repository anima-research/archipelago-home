import { test } from 'node:test';
import assert from 'node:assert/strict';
import { clientIp } from '../src/server.js';

const req = (peer: string, real?: string, header = 'x-real-ip') => ({ socket: { remoteAddress: peer }, headers: real === undefined ? {} : { [header]: real } }) as any;

test('behind the local proxy, X-Real-IP is the client', () => {
  assert.equal(clientIp(req('127.0.0.1', '203.0.113.5')), '203.0.113.5');
  assert.equal(clientIp(req('::1', '2001:db8::7')), '2001:db8::7');
});

test('a direct client cannot pick its own rate-limit bucket', () => {
  assert.equal(clientIp(req('198.51.100.9', '203.0.113.5')), '198.51.100.9');
  assert.equal(clientIp(req('127.0.0.1')), '127.0.0.1');
});

test('a named proxy header is trusted from any peer (platform edge not on loopback)', () => {
  assert.equal(clientIp(req('10.0.0.7', '203.0.113.5'), 'x-real-ip'), '203.0.113.5');
  assert.equal(clientIp(req('10.0.0.7', '203.0.113.5', 'x-client-ip'), 'x-client-ip'), '203.0.113.5');
  assert.equal(clientIp(req('10.0.0.7', '203.0.113.5', 'x-real-ip'), 'x-client-ip'), '10.0.0.7'); // only that header
  assert.equal(clientIp(req('10.0.0.7'), 'x-real-ip'), '10.0.0.7');
});
