#!/usr/bin/env node
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { gzipSync } from 'node:zlib';
import { addressAllowed, createSafeHttpClient } from '../scripts/lib/safe-http.mjs';

let crossOrigin;
let primaryRequests = 0;
let secondaryRequests = 0;
let redirectFinalRequests = 0;

const secondary = createServer((_req, res) => {
  secondaryRequests += 1;
  res.end('must not be reached');
});
const primary = createServer((req, res) => {
  primaryRequests += 1;
  if (req.url === '/same-redirect') {
    res.writeHead(302, { location: '/ok' });
    res.end();
  } else if (req.url === '/cross-redirect') {
    res.writeHead(302, { location: crossOrigin });
    res.end();
  } else if (req.url === '/gzip') {
    res.writeHead(200, { 'content-encoding': 'gzip' });
    res.end(gzipSync('a'.repeat(4096)));
  } else if (req.url === '/bytes') {
    res.end('b'.repeat(600));
  } else if (req.url === '/budget-redirect') {
    res.writeHead(302, { location: '/budget-final' });
    res.end();
  } else if (req.url === '/budget-final') {
    redirectFinalRequests += 1;
    res.end('final');
  } else if (req.url === '/slow-body') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.write('started');
    setTimeout(() => { if (!res.destroyed) res.end('finished'); }, 250);
  } else {
    res.end('ok');
  }
});

const expectCode = async (promise, code) => {
  await assert.rejects(promise, (error) => error?.code === code, code);
};

try {
  primary.listen(0, '127.0.0.1');
  secondary.listen(0, '127.0.0.1');
  await Promise.all([once(primary, 'listening'), once(secondary, 'listening')]);
  const primaryPort = primary.address().port;
  crossOrigin = `http://other.example:${secondary.address().port}/target`;
  const pinnedLookup = async () => [{ address: '127.0.0.1', family: 4 }];

  assert.equal(addressAllowed('127.0.0.1', true), true);
  assert.equal(addressAllowed('10.0.0.1', true), true);
  assert.equal(addressAllowed('169.254.169.254', true), false, 'metadata/link-local stays blocked');
  assert.equal(addressAllowed('::ffff:7f00:1', true), true, 'mapped loopback requires the explicit private opt-in');
  assert.equal(addressAllowed('::ffff:a9fe:a9fe', true), false, 'mapped metadata stays blocked');

  const direct = createSafeHttpClient({ origin: `http://127.0.0.1:${primaryPort}` });
  await expectCode(direct.request(`http://127.0.0.1:${primaryPort}/ok`), 'private_network_blocked');
  assert.equal(primaryRequests, 0, 'literal private target must be rejected before HTTP');

  const dnsBlocked = createSafeHttpClient({ origin: `http://public.example:${primaryPort}`, lookup: pinnedLookup });
  await expectCode(dnsBlocked.request(`http://public.example:${primaryPort}/ok`), 'private_network_blocked');
  assert.equal(primaryRequests, 0, 'private DNS result must be rejected before HTTP');

  let lookups = 0;
  const allowed = createSafeHttpClient({
    origin: `http://public.example:${primaryPort}`,
    lookup: async (...args) => { lookups += 1; return pinnedLookup(...args); },
    allowPrivateNetwork: true,
  });
  const redirected = await allowed.request(`http://public.example:${primaryPort}/same-redirect`, { redirect: 'follow' });
  assert.equal(redirected.status, 200);
  assert.equal(redirected.finalUrl, `http://public.example:${primaryPort}/ok`);
  assert.equal(lookups, 2, 'DNS must be validated again on the redirect hop');
  await expectCode(
    allowed.request(`http://public.example:${primaryPort}/cross-redirect`, { redirect: 'follow' }),
    'cross_origin_request_blocked',
  );
  assert.equal(secondaryRequests, 0, 'cross-origin redirect target must never receive a request');

  const compressed = createSafeHttpClient({
    origin: `http://public.example:${primaryPort}`,
    lookup: pinnedLookup,
    allowPrivateNetwork: true,
    maxResponseBytes: 1024,
  });
  await expectCode(compressed.request(`http://public.example:${primaryPort}/gzip`), 'response_decoded_limit_exceeded');

  const total = createSafeHttpClient({
    origin: `http://public.example:${primaryPort}`,
    lookup: pinnedLookup,
    allowPrivateNetwork: true,
    maxResponseBytes: 1024,
    maxTotalBytes: 1000,
  });
  await total.request(`http://public.example:${primaryPort}/bytes`);
  await expectCode(total.request(`http://public.example:${primaryPort}/bytes`), 'total_body_limit_exceeded');
  assert.equal(total.snapshot().decodedBytes, 600);

  const requestBound = createSafeHttpClient({
    origin: `http://public.example:${primaryPort}`,
    lookup: pinnedLookup,
    allowPrivateNetwork: true,
    maxRequests: 1,
  });
  await expectCode(
    requestBound.request(`http://public.example:${primaryPort}/budget-redirect`, { redirect: 'follow' }),
    'request_budget_exceeded',
  );
  assert.equal(requestBound.snapshot().requests, 1);
  assert.equal(redirectFinalRequests, 0, 'redirect hop over budget must not be requested');

  const timed = createSafeHttpClient({
    origin: `http://public.example:${primaryPort}`,
    lookup: pinnedLookup,
    allowPrivateNetwork: true,
    timeoutMs: 50,
  });
  await expectCode(timed.request(`http://public.example:${primaryPort}/slow-body`), 'request_timeout');

  const dnsTimed = createSafeHttpClient({
    origin: `http://public.example:${primaryPort}`,
    lookup: async () => new Promise(() => {}),
    timeoutMs: 30,
  });
  await expectCode(dnsTimed.request(`http://public.example:${primaryPort}/ok`), 'request_timeout');

  console.log('safe HTTP boundary ok: address, redirect, DNS, byte, request and timeout limits');
} finally {
  primary.closeAllConnections();
  secondary.closeAllConnections();
  await Promise.all([
    new Promise((resolve) => primary.close(resolve)),
    new Promise((resolve) => secondary.close(resolve)),
  ]);
}
