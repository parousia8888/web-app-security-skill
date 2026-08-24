#!/usr/bin/env node
/**
 * crawl-surface-audit.mjs — audit a site's public crawl boundary.
 *
 * Read-only HTTP GET/HEAD only. Run against your own property or with written
 * authorization. See ../references/crawl-boundary.md for how to read the output.
 *
 * Usage:
 *   node crawl-surface-audit.mjs --site https://example.com [options]
 *
 * Options:
 *   --site <url>        required, origin to audit
 *   --out <dir>         write v2 report bundle + raw observations (default: stdout only)
 *   --report-name <s>   stable basename in --out (default: timestamped)
 *   --max-urls <n>      sitemap URLs to spot-check (default 20)
 *   --matrix <n>        URLs to replay across the crawler UA matrix (default 3)
 *   --concurrency <n>   parallel requests (default 4)
 *   --delay <ms>        delay between request batches (default 200)
 *   --timeout <ms>      per-request timeout (default 15000)
 *   --max-response-bytes <n>
 *                       wire and decoded bytes per response (default 4194304)
 *   --max-total-bytes <n>
 *                       decoded bytes across the audit (default 33554432)
 *   --max-requests <n>  HTTP requests including redirect hops (default 256)
 *   --max-redirects <n> same-origin redirects per request (default 5)
 *   --allow-private-network
 *                       explicitly allow localhost/RFC1918 audit origins
 *   --active-probe      probe common private/sensitive paths (requires authorization)
 *   --acknowledge-authorization
 *                       confirm ownership or written authorization for active probes
 *   --fail-on <level>   exit 1 at high, medium, low, or never (default high)
 *   --fail-on-domain <domain=level>
 *                       override one domain threshold; may be repeated
 *   --baseline <json>   compare with a compatible persisted v2 crawl report
 *   --subject-id <id>   explicit persisted subject identity for repeatable audits
 *   --scope-id <id>     stable scope binding used with --subject-id
 *   --mode <mode>       audit, retest, demo-before, or demo-after (default audit)
 *   --quiet             suppress progress output on stderr
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { parseRobots, robotsVerdict } from './lib/robots.mjs';
import {
  assertComparableBaseline, compareFindingsV2, createFindingV2, createReportV2, exitCodeV2,
  initializeFindingsV2, policyForFailOn, readBaselineV2, renderMarkdownV2, writeReportBundleV2,
} from './lib/evidence-v2.mjs';
import { crawlCoverage, CRAWL_ADAPTER, crawlRule, crawlRuleset } from './lib/crawl-rules.mjs';
import { digestValue } from './lib/project-identity.mjs';
import { addressAllowed, addressPolicy, createSafeHttpClient } from './lib/safe-http.mjs';

// ---------------------------------------------------------------- args

const argv = process.argv.slice(2);
const arg = (name, fallback = null) => {
  const i = argv.indexOf(`--${name}`);
  return i === -1 ? fallback : argv[i + 1];
};
const flag = (name) => argv.includes(`--${name}`);
const all = (name) => argv.reduce((values, value, index) =>
  (value === `--${name}` ? [...values, argv[index + 1]] : values), []);

const SITE = arg('site');
if (!SITE) {
  console.error('error: --site <url> is required');
  process.exit(2);
}
let parsedSite;
try { parsedSite = new URL(SITE); } catch { console.error('error: --site must be a valid URL'); process.exit(2); }
if (!['http:', 'https:'].includes(parsedSite.protocol)) {
  console.error('error: --site must use http:// or https://');
  process.exit(2);
}
if (parsedSite.username || parsedSite.password) {
  console.error('error: --site must not contain URL credentials');
  process.exit(2);
}
const ORIGIN = parsedSite.origin;
const OUT_DIR = arg('out');
const REPORT_NAME = arg('report-name');
const BASELINE_PATH = arg('baseline');
const SUBJECT_ID = arg('subject-id');
const SCOPE_ID = arg('scope-id');
const MODE = arg('mode', 'audit');
const MAX_URLS = Number(arg('max-urls', 20));
const MATRIX_URLS = Number(arg('matrix', 3));
const CONCURRENCY = Number(arg('concurrency', 4));
const DELAY = Number(arg('delay', 200));
const TIMEOUT = Number(arg('timeout', 15000));
const MAX_RESPONSE_BYTES = Number(arg('max-response-bytes', 4 * 1024 * 1024));
const MAX_TOTAL_BYTES = Number(arg('max-total-bytes', 32 * 1024 * 1024));
const MAX_REQUESTS = Number(arg('max-requests', 256));
const MAX_REDIRECTS = Number(arg('max-redirects', 5));
const ALLOW_PRIVATE_NETWORK = flag('allow-private-network');
const PROBE = flag('active-probe') && !flag('no-probe');
const ACKNOWLEDGED = flag('acknowledge-authorization');
const FAIL_ON = arg('fail-on', 'high');
const FAIL_ON_DOMAINS = all('fail-on-domain');
const QUIET = flag('quiet');
let EFFECTIVE_POLICY;

for (const [name, value, min, max] of [
  ['max-urls', MAX_URLS, 0, 1000], ['matrix', MATRIX_URLS, 0, 20],
  ['concurrency', CONCURRENCY, 1, 32], ['delay', DELAY, 0, 60000], ['timeout', TIMEOUT, 100, 120000],
  ['max-response-bytes', MAX_RESPONSE_BYTES, 1024, 16 * 1024 * 1024],
  ['max-total-bytes', MAX_TOTAL_BYTES, 1024, 128 * 1024 * 1024],
  ['max-requests', MAX_REQUESTS, 1, 5000], ['max-redirects', MAX_REDIRECTS, 0, 10],
]) {
  if (!Number.isInteger(value) || value < min || value > max) {
    console.error(`error: --${name} must be an integer from ${min} to ${max}`);
    process.exit(2);
  }
}
if (MAX_TOTAL_BYTES < MAX_RESPONSE_BYTES) {
  console.error('error: --max-total-bytes must be greater than or equal to --max-response-bytes');
  process.exit(2);
}
const siteHostname = parsedSite.hostname.replace(/^\[|\]$/g, '');
const literalPolicy = addressPolicy(siteHostname);
const localhostName = siteHostname === 'localhost' || siteHostname.endsWith('.localhost');
if ((literalPolicy.family && !addressAllowed(siteHostname, ALLOW_PRIVATE_NETWORK))
    || (localhostName && !ALLOW_PRIVATE_NETWORK)) {
  const reason = localhostName ? 'localhost' : literalPolicy.reason;
  const hint = addressAllowed(siteHostname, true) || localhostName ? '; pass --allow-private-network only for an explicitly authorized local target' : '';
  console.error(`error: --site uses a blocked ${reason} address${hint}`);
  process.exit(2);
}
if (!['high', 'medium', 'low', 'never'].includes(FAIL_ON)) {
  console.error('error: --fail-on must be high, medium, low, or never');
  process.exit(2);
}
try {
  EFFECTIVE_POLICY = policyForFailOn(FAIL_ON, FAIL_ON_DOMAINS);
} catch (error) {
  console.error(`error: ${error.message}`);
  process.exit(2);
}
if (PROBE && !ACKNOWLEDGED) {
  console.error('error: --active-probe requires --acknowledge-authorization');
  process.exit(2);
}
if (REPORT_NAME && !/^[a-zA-Z0-9._-]+$/.test(REPORT_NAME)) {
  console.error('error: --report-name may contain only letters, digits, dot, underscore, and dash');
  process.exit(2);
}
if (!['audit', 'retest', 'demo-before', 'demo-after'].includes(MODE)) {
  console.error('error: --mode must be audit, retest, demo-before, or demo-after');
  process.exit(2);
}
if (MODE === 'retest' && !BASELINE_PATH) {
  console.error('error: --mode retest requires --baseline');
  process.exit(2);
}
if (Boolean(SUBJECT_ID) !== Boolean(SCOPE_ID)) {
  console.error('error: --subject-id and --scope-id must be supplied together');
  process.exit(2);
}
if (SUBJECT_ID && !/^project-[a-f0-9]{32}$/.test(SUBJECT_ID)) {
  console.error('error: --subject-id must match project- followed by 32 lowercase hex characters');
  process.exit(2);
}
if (SCOPE_ID && !/^[a-zA-Z0-9._-]{3,128}$/.test(SCOPE_ID)) {
  console.error('error: --scope-id contains unsupported characters');
  process.exit(2);
}
if (BASELINE_PATH && !SUBJECT_ID) {
  console.error('error: baseline comparison requires explicit --subject-id and --scope-id');
  process.exit(2);
}

const log = (...m) => { if (!QUIET) console.error('·', ...m); };

function timestamp() {
  const now = process.env.SOURCE_DATE_EPOCH
    ? new Date(Number(process.env.SOURCE_DATE_EPOCH) * 1000)
    : new Date();
  if (Number.isNaN(now.getTime())) {
    console.error('error: SOURCE_DATE_EPOCH must be numeric');
    process.exit(2);
  }
  return now.toISOString();
}

// ---------------------------------------------------------------- constants

const BROWSER_UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36';

// token -> full UA string. Kept realistic; some edges match on the full string.
const UA_MATRIX = {
  browser: BROWSER_UA,
  Googlebot: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
  Bingbot: 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
  'OAI-SearchBot': 'Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)',
  GPTBot: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.1; +https://openai.com/gptbot',
  'ChatGPT-User': 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot',
  ClaudeBot: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)',
  'Claude-SearchBot': 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-SearchBot/1.0; +https://www.anthropic.com)',
  'Claude-User': 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +https://www.anthropic.com)',
  PerplexityBot: 'Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)',
  Applebot: 'Mozilla/5.0 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)',
};

// Crawlers whose absence from robots.txt named groups is worth reporting,
// grouped by what blocking them actually costs.
const UA_ROLES = {
  Googlebot: 'search', Bingbot: 'search', 'OAI-SearchBot': 'ai-search',
  'Claude-SearchBot': 'ai-search', PerplexityBot: 'ai-search', Applebot: 'search',
  DuckAssistBot: 'ai-search', Baiduspider: 'search', YandexBot: 'search',
  'ChatGPT-User': 'user-triggered', 'Claude-User': 'user-triggered', 'Perplexity-User': 'user-triggered',
  GPTBot: 'training', ClaudeBot: 'training', CCBot: 'training',
  'Google-Extended': 'training-token', 'Applebot-Extended': 'training-token',
  Bytespider: 'training', 'meta-externalagent': 'training',
  AhrefsBot: 'seo-tool', SemrushBot: 'seo-tool', DotBot: 'seo-tool', MJ12bot: 'seo-tool',
};

// Paths that must never return a useful 200 to an unauthenticated client.
const PRIVATE_PROBES = [
  '/.env', '/.git/config', '/.git/HEAD', '/.aws/credentials', '/.DS_Store',
  '/config.json', '/package.json', '/composer.lock', '/docker-compose.yml',
  '/backup.zip', '/db.sql', '/dump.sql', '/wp-login.php', '/phpmyadmin/',
  '/admin', '/administrator', '/actuator/env', '/debug', '/metrics', '/server-status',
  '/api/', '/api/v1/keys', '/.well-known/security.txt',
];

// ---------------------------------------------------------------- http

const signals = [];
const add = (severity, code, message, detail, state = 'confirmed') =>
  signals.push({ severity, code, state, message, ...(detail ? { detail } : {}) });
const http = createSafeHttpClient({
  origin: ORIGIN,
  allowPrivateNetwork: ALLOW_PRIVATE_NETWORK,
  timeoutMs: TIMEOUT,
  maxResponseBytes: MAX_RESPONSE_BYTES,
  maxTotalBytes: MAX_TOTAL_BYTES,
  maxRequests: MAX_REQUESTS,
  maxRedirects: MAX_REDIRECTS,
});

async function req(url, { method = 'GET', ua = BROWSER_UA, redirect = 'manual' } = {}) {
  try {
    const res = await http.request(url, {
      method,
      redirect,
      headers: { 'user-agent': ua, accept: '*/*', 'accept-language': 'en-US,en;q=0.9' },
    });
    return {
      ...res,
      ok: true,
      location: res.headers.location || null,
    };
  } catch (e) {
    const errorCode = e.code || 'request_failed';
    return {
      url, ok: false, status: 0, headers: {}, body: '', bytes: 0, errorCode,
      error: `${errorCode}: ${String(e.message || e)}`,
    };
  }
}

async function pool(items, fn) {
  const out = [];
  for (let i = 0; i < items.length; i += CONCURRENCY) {
    const batch = items.slice(i, i + CONCURRENCY);
    out.push(...(await Promise.all(batch.map(fn))));
    if (DELAY && i + CONCURRENCY < items.length) await new Promise((r) => setTimeout(r, DELAY));
  }
  return out;
}

// ---------------------------------------------------------------- robots.txt

// ---------------------------------------------------------------- sitemap

function decodeXmlEntities(text) {
  const named = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
  if (/&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-f]+);)/i.test(text)) {
    throw new Error('unknown or unescaped XML entity');
  }
  return text.replace(/&([^;]+);/g, (_match, entity) => {
    if (Object.hasOwn(named, entity)) return named[entity];
    let point;
    if (/^#\d+$/.test(entity)) point = Number(entity.slice(1));
    else if (/^#x[0-9a-f]+$/i.test(entity)) point = Number.parseInt(entity.slice(2), 16);
    else throw new Error(`unknown XML entity &${entity};`);
    const legal = point === 0x9 || point === 0xa || point === 0xd
      || (point >= 0x20 && point <= 0xd7ff)
      || (point >= 0xe000 && point <= 0xfffd)
      || (point >= 0x10000 && point <= 0x10ffff);
    if (!legal) throw new Error(`invalid numeric XML entity &${entity};`);
    return String.fromCodePoint(point);
  });
}

function parseSitemapXml(xml) {
  if (/<!DOCTYPE\b/i.test(xml)) throw new Error('DOCTYPE/external declarations are not supported');
  if (/<!ENTITY\b/i.test(xml)) throw new Error('external entity declarations are not supported');

  const stack = [];
  const locs = [];
  let root = null;
  let locText = null;
  let cursor = 0;
  const localName = (name) => name.split(':').pop().toLowerCase();

  while (cursor < xml.length) {
    if (xml[cursor] !== '<') {
      const end = xml.indexOf('<', cursor);
      const raw = xml.slice(cursor, end === -1 ? xml.length : end);
      const decoded = decodeXmlEntities(raw);
      if (locText !== null) locText += decoded;
      cursor = end === -1 ? xml.length : end;
      continue;
    }
    if (xml.startsWith('<!--', cursor)) {
      const end = xml.indexOf('-->', cursor + 4);
      if (end === -1) throw new Error('unclosed XML comment');
      cursor = end + 3;
      continue;
    }
    if (xml.startsWith('<![CDATA[', cursor)) {
      const end = xml.indexOf(']]>', cursor + 9);
      if (end === -1) throw new Error('unclosed CDATA section');
      if (locText !== null) locText += xml.slice(cursor + 9, end);
      cursor = end + 3;
      continue;
    }
    if (xml.startsWith('<?', cursor)) {
      const end = xml.indexOf('?>', cursor + 2);
      if (end === -1) throw new Error('unclosed XML processing instruction');
      cursor = end + 2;
      continue;
    }
    if (xml.startsWith('<!', cursor)) throw new Error('unsupported XML declaration');

    let end = cursor + 1;
    let quote = null;
    for (; end < xml.length; end += 1) {
      const char = xml[end];
      if (quote) {
        if (char === quote) quote = null;
      } else if (char === '"' || char === "'") quote = char;
      else if (char === '>') break;
    }
    if (end >= xml.length || quote) throw new Error('unclosed XML tag');
    const tag = xml.slice(cursor, end + 1);
    const close = /^<\/\s*([A-Za-z_][\w:.-]*)\s*>$/.exec(tag);
    if (close) {
      const expected = stack.pop();
      if (!expected || expected !== close[1]) {
        throw new Error(`mismatched closing tag </${close[1]}>; expected ${expected ? `</${expected}>` : 'none'}`);
      }
      if (localName(close[1]) === 'loc') {
        locs.push((locText || '').trim());
        locText = null;
      }
      cursor = end + 1;
      continue;
    }
    const open = /^<\s*([A-Za-z_][\w:.-]*)\b/.exec(tag);
    if (!open) throw new Error(`malformed XML tag near byte ${cursor}`);
    const selfClosing = /\/\s*>$/.test(tag);
    const name = open[1];
    const local = localName(name);
    if (!root) root = local;
    if (locText !== null && local !== 'loc') throw new Error('<loc> may not contain child elements');
    if (local === 'loc') {
      if (locText !== null) throw new Error('nested <loc> element');
      locText = '';
    }
    if (!selfClosing) stack.push(name);
    else if (local === 'loc') {
      locs.push('');
      locText = null;
    }
    cursor = end + 1;
  }

  if (stack.length) throw new Error(`unclosed XML tag <${stack[stack.length - 1]}>`);
  if (!['urlset', 'sitemapindex'].includes(root)) throw new Error('root element must be <urlset> or <sitemapindex>');
  if (locs.some((loc) => !loc)) throw new Error('empty <loc> element');
  return { type: root, locs };
}

function scopedHttpUrl(value, base) {
  let parsed;
  try { parsed = new URL(value, base); } catch { throw new Error(`invalid sitemap URL: ${value}`); }
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error(`unsupported sitemap URL protocol: ${parsed.protocol}`);
  if (parsed.origin !== ORIGIN) throw new Error(`sitemap URL is outside the audited origin: ${parsed.origin}`);
  return parsed.href;
}

function addSitemapUnknown(url, message) {
  add('high', 'sitemap-parse-unknown', message, { url, subject: url }, 'unknown');
}

async function collectSitemap(url, seen = new Set(), depth = 0) {
  let scoped;
  try { scoped = scopedHttpUrl(url, ORIGIN); } catch (error) {
    const message = String(error.message || error);
    addSitemapUnknown(String(url), message);
    return { urls: [], maps: [{ url: String(url), status: 0, bytes: 0, parseState: 'unknown', parseError: message }] };
  }
  if (depth > 2 || seen.has(scoped)) return { urls: [], maps: [] };
  seen.add(scoped);
  const res = await req(scoped);
  const map = { url: scoped, status: res.status, bytes: res.bytes, parseState: 'not-parsed', error: res.error || null };
  const maps = [map];
  if (res.status === 0) {
    map.parseState = 'unknown';
    add('high', 'sitemap-fetch-unknown', `Sitemap evidence could not be fetched: ${res.error}.`,
      { url: scoped, subject: scoped }, 'unknown');
    return { urls: [], maps };
  }
  if (res.status !== 200 || !res.body) return { urls: [], maps };

  let parsed;
  try {
    parsed = parseSitemapXml(res.body);
    map.parseState = 'confirmed';
  } catch (error) {
    map.parseState = 'unknown';
    map.parseError = String(error.message || error);
    addSitemapUnknown(scoped, map.parseError);
    return { urls: [], maps };
  }
  if (parsed.type === 'sitemapindex') {
    const urls = [];
    for (const child of parsed.locs.slice(0, 10)) {
      const sub = await collectSitemap(child, seen, depth + 1);
      const childUnknown = sub.maps.find((entry) => entry.parseState === 'unknown');
      if (childUnknown) {
        map.parseState = 'unknown';
        map.parseError = `child sitemap evidence is unknown: ${childUnknown.url}`;
      }
      urls.push(...sub.urls);
      maps.push(...sub.maps);
    }
    if (map.parseState === 'unknown') return { urls: [], maps };
    return { urls, maps };
  }
  try {
    return { urls: parsed.locs.map((loc) => scopedHttpUrl(loc, scoped)), maps };
  } catch (error) {
    map.parseState = 'unknown';
    map.parseError = String(error.message || error);
    addSitemapUnknown(scoped, map.parseError);
    return { urls: [], maps };
  }
}

// ---------------------------------------------------------------- main

const observations = {
  schemaVersion: 1,
  adapter: CRAWL_ADAPTER.id,
  site: ORIGIN,
  generatedAt: timestamp(),
  robots: null,
  llms: null,
  sitemaps: [],
  sitemapUrlCount: 0,
  sampledUrls: [],
  uaMatrix: [],
  privateProbes: [],
};

log(`auditing ${ORIGIN}`);

// --- robots.txt
const robotsRes = await req(`${ORIGIN}/robots.txt`);
let robots = null;
if (robotsRes.status === 200 && /disallow|allow|user-agent/i.test(robotsRes.body)) {
  robots = parseRobots(robotsRes.body);
  observations.robots = {
    status: 200,
    bytes: robotsRes.bytes,
    groupCount: robots.groups.length,
    agents: robots.groups.flatMap((g) => g.agents),
    sitemaps: robots.sitemaps,
  };
  log(`robots.txt: ${robots.groups.length} groups, ${robots.sitemaps.length} sitemap refs`);

  // finding: named groups that omit the private rules present in `*`
  const star = robots.groups.find((g) => g.agents.includes('*'));
  if (star) {
    const starDisallows = star.rules.filter((r) => r.type === 'disallow' && r.path).map((r) => r.path);
    for (const g of robots.groups) {
      if (g.agents.includes('*')) continue;
      const own = new Set(g.rules.filter((r) => r.type === 'disallow').map((r) => r.path));
      const missing = starDisallows.filter((p) => !own.has(p));
      const blanket = g.rules.some((r) => r.type === 'disallow' && r.path === '/');
      if (missing.length && !blanket) {
        add('medium', 'robots-group-not-inherited',
          `Group "${g.agents.join(', ')}" omits Disallow rules that exist under "*"; crawlers matching their own group ignore the "*" group entirely.`,
          { missing });
      }
    }
  } else {
    add('low', 'robots-no-wildcard-group', 'robots.txt has no "User-agent: *" group; unlisted crawlers get no rules at all.');
  }

  // finding: duplicate groups for the same agent
  const agentCounts = {};
  for (const g of robots.groups) for (const a of g.agents) agentCounts[a] = (agentCounts[a] || 0) + 1;
  const dupes = Object.entries(agentCounts).filter(([, n]) => n > 1).map(([a]) => a);
  if (dupes.length) add('low', 'robots-duplicate-groups', 'Duplicate groups for the same user-agent; merge behaviour is vendor-specific.', { agents: dupes });

  // finding: policy summary per known crawler
  const policy = {};
  for (const [token, role] of Object.entries(UA_ROLES)) {
    const v = robotsVerdict(robots, token, '/');
    policy[token] = { role, rootAllowed: v.allowed, hasOwnGroup: Boolean(v.namedGroup) };
    if (!v.allowed && (role === 'search' || role === 'ai-search')) {
      add('high', 'robots-blocks-search-crawler',
        `robots.txt disallows "/" for ${token} (${role}); this removes you from that engine's index and from AI answers sourced from it.`);
    }
    if (!v.allowed && role === 'user-triggered') {
      add('medium', 'robots-blocks-user-fetcher',
        `robots.txt disallows "/" for ${token}; this is a live user asking an assistant to open your page, and they will see a fetch failure.`);
    }
  }
  observations.robots.policy = policy;

  // finding: no sitemap declared
  if (!robots.sitemaps.length) add('medium', 'robots-no-sitemap', 'robots.txt declares no Sitemap:. Crawlers must then discover every URL by link.');

  // finding: wildcard-suffix rules that many crawlers ignore
  const dollarRules = robots.groups.flatMap((g) => g.rules).filter((r) => r.path.includes('$'));
  if (dollarRules.length) {
    add('info', 'robots-uses-dollar-anchor',
      '"$" anchors are honoured by major crawlers but not universally; do not rely on them for anything that matters.',
      { rules: [...new Set(dollarRules.map((r) => `${r.type}: ${r.path}`))] });
  }
} else if (robotsRes.status === 0) {
  add('high', 'robots-fetch-unknown', `robots.txt evidence could not be fetched: ${robotsRes.error}.`,
    { url: `${ORIGIN}/robots.txt`, subject: `${ORIGIN}/robots.txt` }, 'unknown');
  observations.robots = { status: 0, error: robotsRes.error || null };
} else if (robotsRes.status === 404) {
  add('medium', 'robots-missing', 'robots.txt returned 404. Every crawler will apply its own defaults.',
    { status: 404, subject: `${ORIGIN}/robots.txt` });
  observations.robots = { status: 404, error: null };
} else {
  add('high', 'robots-http-error', `robots.txt returned HTTP ${robotsRes.status}; the published crawl policy is unavailable.`,
    { status: robotsRes.status, subject: `${ORIGIN}/robots.txt` });
  observations.robots = { status: robotsRes.status, error: robotsRes.error || null };
}

// --- llms.txt
const llmsRes = await req(`${ORIGIN}/llms.txt`);
if (llmsRes.status === 200) {
  const urls = [...llmsRes.body.matchAll(/https?:\/\/[^\s)>\]"']+/g)].map((m) => m[0]);
  observations.llms = { status: 200, bytes: llmsRes.bytes, urlCount: urls.length, urls: urls.slice(0, 200) };
  log(`llms.txt: ${urls.length} URLs`);
  const foreign = urls.filter((u) => { try { return new URL(u).origin !== ORIGIN; } catch { return false; } });
  if (foreign.length) add('info', 'llms-external-urls', 'llms.txt references external origins.', { count: foreign.length });
  if (robots) {
    const blocked = urls.filter((u) => {
      try { const p = new URL(u); return p.origin === ORIGIN && !robotsVerdict(robots, 'Googlebot', p.pathname).allowed; }
      catch { return false; }
    });
    if (blocked.length) add('medium', 'llms-lists-disallowed-urls', 'llms.txt advertises URLs that robots.txt disallows.', { urls: blocked.slice(0, 20) });
  }
} else {
  observations.llms = { status: llmsRes.status, error: llmsRes.error || null };
  if (llmsRes.status === 0) add('low', 'llms-fetch-unknown', `llms.txt evidence could not be fetched: ${llmsRes.error}.`,
    { url: `${ORIGIN}/llms.txt`, subject: `${ORIGIN}/llms.txt` }, 'unknown');
}

// --- sitemaps
const sitemapCandidates = robots?.sitemaps?.length ? robots.sitemaps : [`${ORIGIN}/sitemap.xml`];
let sitemapUrls = [];
for (const sm of sitemapCandidates.slice(0, 5)) {
  const { urls, maps } = await collectSitemap(sm);
  observations.sitemaps.push(...maps);
  sitemapUrls.push(...urls);
}
sitemapUrls = [...new Set(sitemapUrls)];
observations.sitemapUrlCount = sitemapUrls.length;
log(`sitemaps: ${observations.sitemaps.length} files, ${sitemapUrls.length} unique URLs`);

for (const m of observations.sitemaps) {
  if (m.status === 0) continue;
  if (m.status !== 200) add('high', 'sitemap-unreachable', `Declared sitemap returned HTTP ${m.status}.`, { url: m.url, subject: m.url });
  else if (robots) {
    try {
      const p = new URL(m.url);
      if (p.origin === ORIGIN && !robotsVerdict(robots, 'Googlebot', p.pathname).allowed) {
        add('high', 'sitemap-disallowed', 'A declared sitemap is itself disallowed by robots.txt.', { url: m.url });
      }
    } catch { /* ignore */ }
  }
}
if (!sitemapUrls.length && observations.sitemaps.length
    && observations.sitemaps.every((map) => map.status === 200 && map.parseState === 'confirmed')) {
  add('high', 'sitemap-empty', 'No URLs discovered from any sitemap.');
}

// --- sample sitemap URLs
const sample = sitemapUrls.slice(0, MAX_URLS);
if (sample.length) log(`spot-checking ${sample.length} sitemap URLs`);
const sampleResults = await pool(sample, async (u) => {
  const res = await req(u, { redirect: 'manual' });
  const xrt = res.headers['x-robots-tag'] || '';
  const meta = /<meta[^>]+name=["']robots["'][^>]+content=["']([^"']+)["']/i.exec(res.body || '');
  const canonical = /<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']+)["']/i.exec(res.body || '');
  let robotsAllowed = true, robotsBy = 'n/a';
  try { const v = robotsVerdict(robots, 'Googlebot', new URL(u).pathname); robotsAllowed = v.allowed; robotsBy = v.by; } catch { /* ignore */ }
  return {
    url: u, status: res.status, bytes: res.bytes, error: res.error || null,
    xRobotsTag: xrt || null, metaRobots: meta ? meta[1] : null,
    canonical: canonical ? canonical[1] : null,
    location: res.location, robotsAllowed, robotsBy,
  };
});
observations.sampledUrls = sampleResults;

for (const r of sampleResults) {
  if (r.status === 0) add('medium', 'sitemap-url-fetch-unknown', `Sitemap URL evidence could not be fetched: ${r.error}.`,
    { url: r.url, subject: r.url }, 'unknown');
  else if (r.status >= 500) add('high', 'sitemap-url-5xx', `Sitemap URL returned ${r.status}.`, { url: r.url });
  else if (r.status === 404 || r.status === 410) add('high', 'sitemap-url-404', `Sitemap URL returned ${r.status}; stale sitemap entries waste crawl budget and look like a broken site.`, { url: r.url });
  else if (r.status >= 300 && r.status < 400) add('medium', 'sitemap-url-redirect', `Sitemap URL redirects (${r.status}); list the final URL instead.`, { url: r.url, to: r.location });
  if (/noindex/i.test(r.xRobotsTag || '') || /noindex/i.test(r.metaRobots || '')) {
    add('high', 'sitemap-url-noindex', 'Sitemap URL is marked noindex — it is being advertised and suppressed at the same time.', { url: r.url });
  }
  if (!r.robotsAllowed) {
    add('high', 'sitemap-url-disallowed', 'Sitemap URL is disallowed by robots.txt. The crawler cannot fetch it, so any noindex or canonical on it is never read.', { url: r.url, rule: r.robotsBy });
  }
  if (r.status === 200 && r.bytes > 0 && r.bytes < 2048) {
    add('medium', 'thin-initial-html', 'Initial HTML is very small; if the content is rendered by JavaScript, most AI crawlers will see an empty page.', { url: r.url, bytes: r.bytes });
  }
  if (r.status === 200 && !r.canonical) {
    add('low', 'missing-canonical', 'No rel=canonical in the initial HTML.', { url: r.url });
  }
}

// --- UA matrix
const matrixTargets = [`${ORIGIN}/`, ...sample.filter((u) => u !== `${ORIGIN}/`).slice(0, Math.max(0, MATRIX_URLS - 1))];
log(`UA matrix across ${matrixTargets.length} URL(s) × ${Object.keys(UA_MATRIX).length} agents`);

for (const target of matrixTargets) {
  const rows = [];
  for (const [token, ua] of Object.entries(UA_MATRIX)) {
    const res = await req(target, { ua, redirect: 'follow' });
    rows.push({ agent: token, status: res.status, bytes: res.bytes, xRobotsTag: res.headers['x-robots-tag'] || null, error: res.error || null });
    if (DELAY) await new Promise((r) => setTimeout(r, DELAY));
  }
  observations.uaMatrix.push({ url: target, rows });

  const base = rows.find((r) => r.agent === 'browser');
  if (!base || base.status === 0) {
    add('high', 'matrix-baseline-unknown', 'Baseline browser evidence could not be fetched; UA comparison did not run.',
      { url: target, status: base?.status || 0, error: base?.error || null, subject: target }, 'unknown');
    continue;
  }
  if (base.status !== 200) {
    add('high', 'baseline-fetch-failed', `Baseline browser returned HTTP ${base.status}; UA comparison did not run.`,
      { url: target, status: base.status, subject: target });
    add('high', 'matrix-comparison-unavailable', 'UA comparison requires a successful browser baseline.',
      { url: target, status: base.status, subject: target }, 'unknown');
    continue;
  }
  for (const r of rows) {
    if (r.agent === 'browser') continue;
    const role = UA_ROLES[r.agent] || 'other';
    if (r.status === 0) {
      add('high', 'crawler-request-unknown', `Request as ${r.agent} failed (${r.error}).`,
        { url: target, agent: r.agent, subject: `${target}#${r.agent}` }, 'unknown');
    } else if (r.status === 403 || r.status === 401 || r.status === 429 || r.status === 503) {
      add('high', 'crawler-blocked',
        `${r.agent} received ${r.status} while a browser received 200 — this crawler is being blocked at the edge/WAF. Check bot-fight / AI-scraper settings and managed rule groups.`,
        { url: target, role });
    } else if (r.status !== base.status) {
      add('medium', 'crawler-status-differs', `${r.agent} received ${r.status} vs ${base.status} for a browser.`, { url: target });
    } else if (base.bytes > 0) {
      const delta = Math.abs(r.bytes - base.bytes) / base.bytes;
      if (delta > 0.25) {
        add('medium', 'possible-cloaking',
          `${r.agent} received a response ${Math.round(delta * 100)}% different in size from the browser response. Serving different content by user agent is cloaking and breaks AI retrieval.`,
          { url: target, crawlerBytes: r.bytes, browserBytes: base.bytes });
      }
    }
    if (/noindex/i.test(r.xRobotsTag || '')) {
      add('high', 'public-page-noindex', `${r.agent} received X-Robots-Tag: ${r.xRobotsTag} on a public page.`, { url: target });
    }
  }
}

// --- private path probes
if (PROBE) {
  // Baseline: does the app return a real 404, or a catch-all 200 (SPA soft-404)?
  const nonce = randomUUID().slice(0, 12);
  const baseline = await req(`${ORIGIN}/__no-such-path-${nonce}`);
  const soft = baseline.status === 200 ? { bytes: baseline.bytes } : null;
  observations.notFoundBaseline = { status: baseline.status, bytes: baseline.bytes, softNotFound: Boolean(soft), error: baseline.error || null };
  if (baseline.status === 0) {
    add('high', 'probe-baseline-unknown', `Unknown-route baseline could not be fetched: ${baseline.error}.`,
      { subject: 'not-found-baseline' }, 'unknown');
  }
  if (soft) {
    add('medium', 'soft-404-catchall',
      'A non-existent path returns 200 with the app shell instead of 404. Crawlers index and re-crawl garbage URLs, real 404s become invisible, and the highest-signal scanner-detection rule (404 ratio per client) stops working. Return a real 404 status for unmatched routes.',
      { probe: `/__no-such-path-${nonce}`, bytes: baseline.bytes });
  }

  log(`probing ${PRIVATE_PROBES.length} private paths`);
  const probeResults = await pool(PRIVATE_PROBES, async (p) => {
    const res = await req(`${ORIGIN}${p}`, { redirect: 'manual' });
    const bodyHint =
      /(BEGIN [A-Z ]*PRIVATE KEY|aws_secret_access_key|[A-Z_]*API[_-]?KEY\s*=|"dependencies"|\[core\]|ref:\s*refs\/)/i.test(res.body || '');
    const isSoft = Boolean(soft) && res.status === 200 &&
      Math.abs(res.bytes - soft.bytes) <= Math.max(512, soft.bytes * 0.02);
    return { path: p, status: res.status, bytes: res.bytes, contentType: res.headers['content-type'] || null, looksSensitive: bodyHint, softNotFound: isSoft, error: res.error || null };
  });
  observations.privateProbes = probeResults;

  const softCount = probeResults.filter((r) => r.softNotFound && !r.looksSensitive).length;
  if (softCount) {
    add('info', 'probe-soft-404', `${softCount} probe path(s) returned the app shell (soft 404), not a real exposure — see soft-404-catchall.`);
  }

  for (const r of probeResults) {
    if (r.status === 0) {
      add('high', 'probe-request-unknown', `Private-path evidence for ${r.path} could not be fetched: ${r.error}.`,
        { path: r.path, subject: r.path }, 'unknown');
    } else if (r.softNotFound && !r.looksSensitive) {
      continue; // reported once as soft-404-catchall
    } else if (r.status === 200 && r.looksSensitive) {
      add('high', 'sensitive-file-exposed', `${r.path} returned 200 with content matching a secret/config pattern.`, { path: r.path, bytes: r.bytes });
    } else if (r.status === 200 && !['/api/', '/.well-known/security.txt'].includes(r.path)) {
      add('medium', 'probe-path-200', `${r.path} returned 200. Confirm this is intentional and contains nothing private.`, { path: r.path, bytes: r.bytes, contentType: r.contentType });
    } else if (r.status === 403) {
      add('low', 'probe-path-403', `${r.path} returned 403, which confirms the path exists. Prefer 404 where existence itself is a hint.`, { path: r.path });
    }
  }
  const notFound = probeResults.filter((r) => r.status === 404).length;
  add('info', 'probe-summary', `${notFound}/${probeResults.length} probe paths returned 404.`);

  // source map spot check derived from the homepage HTML
  const home = await req(`${ORIGIN}/`);
  const scripts = [...(home.body || '').matchAll(/<script[^>]+src=["']([^"']+)["']/gi)].map((m) => m[1]);
  const firstJs = scripts.map((s) => { try { return new URL(s, ORIGIN).href; } catch { return null; } }).filter((s) => s && s.startsWith(ORIGIN) && s.includes('.js'))[0];
  if (firstJs) {
    const mapUrl = `${firstJs.split('?')[0]}.map`;
    const mapRes = await req(mapUrl, { method: 'HEAD' });
    observations.sourceMap = { url: mapUrl, status: mapRes.status, error: mapRes.error || null };
    if (mapRes.status === 200) {
      add('high', 'source-map-exposed', 'A production source map is publicly served; it reconstructs original sources and comments.', { url: mapUrl });
    } else if (mapRes.status === 0) {
      add('high', 'source-map-check-unknown', `Source-map evidence could not be fetched: ${mapRes.error}.`,
        { url: mapUrl, subject: mapUrl }, 'unknown');
    }
  } else if (home.status === 0) {
    add('high', 'source-map-discovery-unknown', `Homepage evidence for source-map discovery could not be fetched: ${home.error}.`,
      { url: `${ORIGIN}/`, subject: `${ORIGIN}/` }, 'unknown');
  }
  if (scripts.some((s) => /\?v=[a-z][a-z0-9-]{4,}/i.test(s))) {
    add('low', 'semantic-cache-buster', 'Asset URLs carry semantic cache-busting values that leak internal release or feature names; use content hashes.');
  }
}

// ---------------------------------------------------------------- output

function surfaceStatus(results, enabled = true) {
  if (!enabled) return 'not_applicable';
  if (!results.length) return 'unavailable';
  const failed = results.filter((item) => item.status === 0 || item.parseState === 'unknown').length;
  if (!failed) return 'completed';
  return failed === results.length ? 'unavailable' : 'partial';
}

const surfaceStatuses = {
  robots: observations.robots?.status === 0 ? 'unavailable' : 'completed',
  llms: observations.llms?.status === 0 ? 'unavailable' : 'completed',
  sitemap: surfaceStatus(observations.sitemaps),
  sample: observations.sitemapUrlCount === 0
    ? 'not_applicable'
    : surfaceStatus(observations.sampledUrls),
  matrix: surfaceStatus(observations.uaMatrix.flatMap((entry) => entry.rows)),
  probe: surfaceStatus(observations.privateProbes, PROBE),
  'source-map': PROBE
    ? observations.sourceMap?.status === 0 || signals.some((signal) => signal.code === 'source-map-discovery-unknown')
      ? 'unavailable'
      : 'completed'
    : 'not_applicable',
};
const ruleset = crawlRuleset();
const coverage = crawlCoverage(signals, surfaceStatuses);
const normalizedSubject = (value) => JSON.stringify(value || {}).replaceAll(ORIGIN, '{origin}');
const current = signals.map((signal) => createFindingV2({
  ruleset,
  adapterId: CRAWL_ADAPTER.id,
  rule: crawlRule(signal.code),
  title: signal.message.split(/[.;]\s/)[0],
  severity: signal.severity,
  state: signal.state,
  summary: signal.message,
  evidence: {
    subject: normalizedSubject(signal.detail?.subject || { code: signal.code, message: signal.message }),
    origin: ORIGIN,
    observation: signal.detail || {},
  },
  remediation: signal.state === 'unknown'
    ? 'Restore the evidence source or required capability, then rerun the same scoped check.'
    : signal.code.startsWith('robots-') || signal.code.startsWith('sitemap-') || signal.code.includes('crawler') || signal.code.includes('noindex')
      ? 'Align the origin, robots, sitemap and edge policy with the intended public crawl boundary.'
      : 'Remove the exposed surface or enforce the intended response at the origin or edge.',
  retest: 'Run the same crawl scope and adapter revision again; do not infer success from an unavailable request.',
}));

const auditBoundary = {
  version: 2,
  surface: 'crawl',
  originBinding: SCOPE_ID || ORIGIN,
  activeProbe: PROBE,
  maxUrls: MAX_URLS,
  matrixUrls: MATRIX_URLS,
  networkPolicy: {
    sameOriginOnly: true,
    dnsPinnedPerHop: true,
    allowPrivateNetwork: ALLOW_PRIVATE_NETWORK,
    maxResponseBytes: MAX_RESPONSE_BYTES,
    maxTotalBytes: MAX_TOTAL_BYTES,
    maxRequests: MAX_REQUESTS,
    maxRedirects: MAX_REDIRECTS,
  },
};
const subject = {
  id: SUBJECT_ID || `project-${randomUUID().replaceAll('-', '').slice(0, 32)}`,
  binding: SUBJECT_ID ? 'persisted' : 'ephemeral',
  scopeDigest: digestValue(auditBoundary),
  localPathIncluded: false,
};
let baseline = null;
let v2Findings;
try {
  if (BASELINE_PATH) {
    const loaded = readBaselineV2(BASELINE_PATH);
    baseline = assertComparableBaseline(subject, loaded.report, loaded.rawBytes);
    if (baseline.sourceDigest !== loaded.sourceDigest) throw new Error('baseline digest metadata is inconsistent');
    v2Findings = compareFindingsV2(current, coverage, loaded.report, ruleset);
  } else {
    v2Findings = initializeFindingsV2(current, coverage);
  }
} catch (error) {
  console.error(`error: ${error.message}`);
  process.exit(2);
}

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const v2Report = createReportV2({
  version: readFileSync(join(ROOT, 'VERSION'), 'utf8').trim(),
  generatedAt: observations.generatedAt,
  mode: MODE,
  subject,
  ruleset,
  scope: {
    auditBoundary,
    authorizationStatus: PROBE ? 'explicitly-acknowledged' : 'passive-only',
    checkModes: PROBE ? ['network-passive', 'network-active'] : ['network-passive'],
    networkAccessPerformed: true,
  },
  coverage,
  findings: v2Findings,
  baseline,
  policy: EFFECTIVE_POLICY,
  limitations: [
    'HTTP observations do not prove application authorization, business logic, identity or data-layer security.',
    'Crawler user-agent replay does not prove that a request originated from a vendor-owned crawler address.',
    `HTTP requests stayed on the initial origin, pinned each DNS-validated redirect hop, and used per-response (${MAX_RESPONSE_BYTES}) and total decoded-byte (${MAX_TOTAL_BYTES}) budgets.`,
    ALLOW_PRIVATE_NETWORK
      ? 'Localhost and private-network origins were explicitly allowed; link-local, multicast and reserved addresses remained blocked.'
      : 'Localhost, private, link-local, multicast and reserved addresses were blocked.',
    PROBE
      ? 'Active probes were limited to the documented bounded path list.'
      : 'Private paths and production source maps were not probed because active mode was disabled.',
  ],
});
observations.network = http.snapshot();
const md = renderMarkdownV2(v2Report);

if (OUT_DIR) {
  const stamp = observations.generatedAt.replace(/[:.]/g, '-');
  const host = new URL(ORIGIN).hostname;
  const base = REPORT_NAME || `crawl-surface-${host}-${stamp}`;
  try {
    writeReportBundleV2(v2Report, OUT_DIR, base, { additionalFiles: [
      { name: `${base}.observations.json`, json: observations },
    ] });
  } catch (error) {
    console.error(`error: ${error.message}`);
    process.exit(2);
  }
  log(`wrote report bundle and raw observations to ${OUT_DIR}`);
}

console.log(md);
process.exit(exitCodeV2(v2Report));
