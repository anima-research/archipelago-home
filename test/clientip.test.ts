import { test } from 'node:test';
import assert from 'node:assert/strict';
import { clientIp } from '../src/server.js';

const req = (peer: string, real?: string) => ({ socket: { remoteAddress: peer }, headers: real === undefined ? {} : { 'x-real-ip': real } }) as any;

test('behind the local proxy, X-Real-IP is the client', () => {
  assert.equal(clientIp(req('127.0.0.1', '203.0.113.5')), '203.0.113.5');
  assert.equal(clientIp(req('::1', '2001:db8::7')), '2001:db8::7');
});

test('a direct client cannot pick its own rate-limit bucket', () => {
  assert.equal(clientIp(req('198.51.100.9', '203.0.113.5')), '198.51.100.9');
  assert.equal(clientIp(req('127.0.0.1')), '127.0.0.1');
});
