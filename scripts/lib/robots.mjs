/**
 * robots.txt parsing + evaluation — shared by crawl-surface-audit.mjs and its tests.
 *
 * Kept as a pure module (no IO) so the tricky bits — most-specific group selection,
 * longest-match wins, Allow breaking ties, `*`/`$` wildcards — are unit-testable.
 * Getting these wrong makes the audit misreport the crawl boundary: a mis-parsed
 * Disallow can make you "confirm" that a public path is blocked, or vice versa.
 */

export function parseRobots(text) {
  const groups = []; // { agents: [], rules: [{type, path}], crawlDelay }
  const sitemaps = [];
  let current = null;
  let lastWasAgent = false;

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const field = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();

    if (field === 'user-agent') {
      if (!current || !lastWasAgent) { current = { agents: [], rules: [], crawlDelay: null }; groups.push(current); }
      current.agents.push(value);
      lastWasAgent = true;
      continue;
    }
    lastWasAgent = false;
    if (field === 'sitemap') { sitemaps.push(value); continue; }
    if (!current) { current = { agents: ['*'], rules: [], crawlDelay: null }; groups.push(current); }
    if (field === 'allow' || field === 'disallow') current.rules.push({ type: field, path: value });
    else if (field === 'crawl-delay') current.crawlDelay = Number(value);
  }
  return { groups, sitemaps };
}

const matcherCache = new WeakMap();

function compileRule(pattern) {
  if (pattern === '') return null;
  const anchored = pattern.endsWith('$');
  const body = anchored ? pattern.slice(0, -1) : pattern;
  return {
    anchored,
    onlyWildcards: body.length > 0 && /^\*+$/.test(body),
    leadingWildcard: body.startsWith('*'),
    trailingWildcard: body.endsWith('*'),
    segments: body.split('*').filter(Boolean),
  };
}

function compiledRuleMatches(compiled, path) {
  if (!compiled) return false;
  const { anchored, leadingWildcard, onlyWildcards, trailingWildcard, segments } = compiled;
  if (!segments.length) return onlyWildcards || path.length === 0;

  let cursor = 0;
  let segmentIndex = 0;
  if (!leadingWildcard) {
    if (!path.startsWith(segments[0])) return false;
    cursor = segments[0].length;
    segmentIndex = 1;
  }

  for (; segmentIndex < segments.length; segmentIndex += 1) {
    const segment = segments[segmentIndex];
    const isLast = segmentIndex === segments.length - 1;
    if (isLast && anchored && !trailingWildcard) {
      const start = path.length - segment.length;
      return start >= cursor && path.endsWith(segment);
    }
    const found = path.indexOf(segment, cursor);
    if (found === -1) return false;
    cursor = found + segment.length;
  }

  return !anchored || trailingWildcard || cursor === path.length;
}

export function ruleMatches(pattern, path) {
  return compiledRuleMatches(compileRule(pattern), String(path));
}

function cachedRuleMatches(rule, path) {
  let compiled = matcherCache.get(rule);
  if (compiled === undefined) {
    compiled = compileRule(rule.path);
    matcherCache.set(rule, compiled);
  }
  return compiledRuleMatches(compiled, path);
}

/** Most-specific group wins (no merging with `*`), longest match wins, Allow breaks ties. */
export function robotsVerdict(robots, uaToken, path) {
  if (!robots) return { allowed: true, by: 'no-robots' };
  const lower = uaToken.toLowerCase();
  let group = robots.groups.find((g) => g.agents.some((a) => a.toLowerCase() === lower));
  if (!group) group = robots.groups.find((g) => g.agents.some((a) => a !== '*' && lower.includes(a.toLowerCase())));
  let matchedNamed = Boolean(group);
  if (!group) group = robots.groups.find((g) => g.agents.includes('*'));
  if (!group) return { allowed: true, by: 'no-group' };

  let best = null;
  for (const rule of group.rules) {
    if (!cachedRuleMatches(rule, path)) continue;
    const len = rule.path.length;
    if (!best || len > best.len || (len === best.len && rule.type === 'allow')) best = { ...rule, len };
  }
  return {
    allowed: best ? best.type === 'allow' : true,
    by: best ? `${best.type}: ${best.path}` : 'default-allow',
    group: group.agents.join(', '),
    namedGroup: matchedNamed,
  };
}
