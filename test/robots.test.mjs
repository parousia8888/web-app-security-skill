#!/usr/bin/env node
/**
 * Unit tests for robots.txt parse + evaluate (scripts/lib/robots.mjs).
 * These defend the crawl-boundary semantics the audit relies on. A wrong verdict here
 * makes the tool "confirm" a public path is blocked (or a private one is open).
 * Pure functions, no IO. Run: node test/robots.test.mjs
 */
import { performance } from 'node:perf_hooks';
import { parseRobots, robotsVerdict, ruleMatches } from '../scripts/lib/robots.mjs';

let failed = 0;
const eq = (name, got, want) => {
  if (got !== want) { failed++; console.error(`✗ ${name}\n    got ${JSON.stringify(got)} · want ${JSON.stringify(want)}`); }
};

// [name, robotsText, uaToken, path, expectedAllowed]
const CASES = [
  ['plain disallow blocks',
    'User-agent: *\nDisallow: /admin', '*', '/admin', false],
  ['plain disallow leaves others open',
    'User-agent: *\nDisallow: /admin', '*', '/about', true],
  ['empty Disallow means allow-all',
    'User-agent: *\nDisallow:', '*', '/anything', true],

  // longest-match + Allow tie-break
  ['Allow carves an exception out of Disallow: / (longest wins)',
    'User-agent: *\nDisallow: /\nAllow: /public', '*', '/public/x', true],
  ['Disallow: / still blocks everything else',
    'User-agent: *\nDisallow: /\nAllow: /public', '*', '/private', false],
  ['equal-length Allow beats Disallow (tie-break)',
    'User-agent: *\nDisallow: /a\nAllow: /a', '*', '/a', true],

  // named group takes precedence over * (the GEO crawl-boundary case)
  ['named crawler gets its own group, not the * group',
    'User-agent: *\nDisallow: /\n\nUser-agent: GPTBot\nAllow: /', 'GPTBot', '/anything', true],
  ['* group still blocks the unnamed crawler',
    'User-agent: *\nDisallow: /\n\nUser-agent: GPTBot\nAllow: /', 'SomeRandomBot', '/anything', false],
  ['Epoch-0-style: * allows all but /me; GPTBot allowed everywhere',
    'User-agent: *\nAllow: /\nDisallow: /me\n\nUser-agent: GPTBot\nAllow: /', 'GPTBot', '/me', true],
  ['...and the * group is still blocked from /me',
    'User-agent: *\nAllow: /\nDisallow: /me\n\nUser-agent: GPTBot\nAllow: /', '*', '/me', false],

  // wildcards
  ['* wildcard in the middle',
    'User-agent: *\nDisallow: /*.pdf', '*', '/docs/secret.pdf', false],
  ['$ anchors the end',
    'User-agent: *\nDisallow: /*.php$', '*', '/index.php', false],
  ['$ anchor: query string after extension is not blocked',
    'User-agent: *\nDisallow: /*.php$', '*', '/index.php?x=1', true],
  ['$ alone matches only the empty path',
    'User-agent: *\nDisallow: $', '*', '/', true],

  // no robots at all → allow
  ['null robots → allowed', null, '*', '/whatever', true],
];

for (const [name, text, ua, path, want] of CASES) {
  const robots = text === null ? null : parseRobots(text);
  eq(name, robotsVerdict(robots, ua, path).allowed, want);
}

// parse structure
const r = parseRobots('User-agent: A\nUser-agent: B\nDisallow: /x\nSitemap: https://e/sm.xml\nCrawl-delay: 5');
eq('consecutive User-agents share one group', r.groups[0].agents.join(','), 'A,B');
eq('sitemap extracted', r.sitemaps[0], 'https://e/sm.xml');
eq('crawl-delay parsed', r.groups[0].crawlDelay, 5);

eq('consecutive wildcards retain wildcard semantics',
  ruleMatches('/docs/***/*.pdf$', '/docs/archive/2026/report.pdf'), true);
const adversarialPattern = `/${'*'.repeat(10000)}never$`;
const adversarialPath = `/${'a'.repeat(10000)}`;
const started = performance.now();
eq('adversarial wildcard pattern does not match', ruleMatches(adversarialPattern, adversarialPath), false);
const elapsed = performance.now() - started;
if (elapsed > 500) {
  failed++;
  console.error(`✗ adversarial wildcard match exceeded budget: ${elapsed.toFixed(1)}ms`);
}

if (failed) { console.error(`\n${failed} assertion(s) failed`); process.exit(1); }
console.log(`✓ robots: ${CASES.length + 5} assertions pass; adversarial wildcard ${elapsed.toFixed(1)}ms`);
