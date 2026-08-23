import { assertRouteSecurityDocument } from './route-security-contract.mjs';

const code = (value) => `\`${String(value).replace(/`/g, '\\`')}\``;
const listCounts = (value) => Object.entries(value).filter(([, count]) => count)
  .map(([key, count]) => `${key}=${count}`).join(', ') || 'none';

export function renderRouteSecurityMarkdown(document) {
  assertRouteSecurityDocument(document);
  const lines = [
    '# Route security review', '',
    `- Tool: ${code(`${document.tool.name} ${document.tool.version}`)}`,
    `- Mode: ${code(document.mode)}`,
    `- Routes inventoried: ${document.summary.total}`,
    `- State-changing: ${document.summary.stateChanging}`,
    `- Object-addressed: ${document.summary.objectAddressed}`,
    '', 'Review priority orders manual work; it is not vulnerability severity. A control marked',
    'observed is static source evidence and does not prove runtime enforcement or correctness.', '',
    '## Summary', '',
    `- Frameworks: ${listCounts(document.summary.byFramework)}`,
    `- Priority: ${listCounts(document.summary.byPriority)}`,
    `- Authentication evidence: ${listCounts(document.summary.byAuthentication)}`,
    `- Authorization evidence: ${listCounts(document.summary.byAuthorization)}`,
    '', '## Coverage', '',
  ];
  if (!document.coverage.length) lines.push('No supported framework coverage was applicable.', '');
  for (const item of document.coverage) {
    const counts = Object.entries(item.counts).map(([key, value]) => `${key}=${value}`).join(', ');
    const reasons = item.reasons.map((reason) => `${reason.code}=${reason.count}`).join(', ');
    lines.push(`- ${code(item.framework)}: ${item.status}; ${counts}${reasons ? `; ${reasons}` : ''}`);
  }
  lines.push('', '## Routes', '');
  if (!document.routes.length) lines.push('No routes were inventoried within the supported syntax boundary.', '');
  for (const route of document.routes) {
    lines.push(
      `### ${route.method} ${route.path ? code(route.path) : '(dynamic path)'}`, '',
      `- Framework: ${code(route.framework)}`,
      `- Source: ${code(`${route.location.path}:${route.location.line || '?'}`)}`,
      `- Review priority: ${code(route.priority.level)}${route.priority.reasons.length ? ` (${route.priority.reasons.join(', ')})` : ''}`,
      `- Baseline: ${route.baseline.state ? code(route.baseline.state) : 'not compared'}`,
      `- Authentication: ${code(route.authentication.state)}. ${route.authentication.boundary}`,
      `- Authorization: ${code(route.authorization.state)}. ${route.authorization.boundary}`,
      `- State-changing: ${route.stateChanging ? 'yes' : 'no'}; object-addressed: ${route.objectAddressed ? 'yes' : 'no'}`,
      `- Sensitive operations: ${route.operations.length ? route.operations.map(code).join(', ') : 'none observed'}`,
      `- Evidence limits: ${route.limitations.length ? route.limitations.map(code).join(', ') : 'none beyond the global limits below'}`,
      '',
    );
  }
  lines.push('## Limitations', '');
  if (!document.limitations.length) lines.push('- Static route evidence does not prove deployed behavior.', '');
  else lines.push(...document.limitations.map((item) => `- ${item}`), '');
  return `${lines.join('\n')}\n`;
}
