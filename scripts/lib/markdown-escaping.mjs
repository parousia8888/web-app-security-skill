function visibleCodeSpanText(value) {
  return String(value)
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
    .replace(/\t/g, '\\t')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

export function markdownCodeSpan(value) {
  const content = visibleCodeSpanText(value);
  let longestRun = 0;
  for (const match of content.matchAll(/`+/g)) longestRun = Math.max(longestRun, match[0].length);
  const fence = '`'.repeat(longestRun + 1);
  const padding = content.startsWith(' ') || content.endsWith(' ') ? ' ' : '';
  return `${fence}${padding}${content}${padding}${fence}`;
}
