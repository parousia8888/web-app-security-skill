import { posix } from 'node:path';

const MAX_TOKENS = 50_000;

function safePath(path) {
  const normalized = posix.normalize(path.replace(/\\/g, '/'));
  return normalized !== '..' && !normalized.startsWith('../') && !posix.isAbsolute(normalized)
    ? normalized : null;
}

function tokens(text) {
  const result = [];
  let index = 0;
  while (index < text.length && result.length < MAX_TOKENS) {
    const current = text[index];
    const next = text[index + 1];
    if (/\s/u.test(current)) {
      index += 1;
      continue;
    }
    if (current === '/' && next === '/') {
      index += 2;
      while (index < text.length && !['\n', '\r'].includes(text[index])) index += 1;
      continue;
    }
    if (current === '/' && next === '*') {
      const end = text.indexOf('*/', index + 2);
      if (end < 0) return null;
      index = end + 2;
      continue;
    }
    if (current === '"') {
      let cursor = index + 1;
      let escaped = false;
      while (cursor < text.length) {
        if (!escaped && text[cursor] === '"') break;
        if (!escaped && text[cursor] === '\\') escaped = true;
        else escaped = false;
        cursor += 1;
      }
      if (cursor >= text.length) return null;
      try {
        result.push({ type: 'string', value: JSON.parse(text.slice(index, cursor + 1)) });
      } catch {
        return null;
      }
      index = cursor + 1;
      continue;
    }
    if (/[A-Za-z_]/u.test(current)) {
      let cursor = index + 1;
      while (/[A-Za-z0-9_-]/u.test(text[cursor] || '')) cursor += 1;
      result.push({ type: 'identifier', value: text.slice(index, cursor) });
      index = cursor;
      continue;
    }
    if (['{', '}', '='].includes(current)) result.push({ type: current, value: current });
    index += 1;
  }
  return index === text.length ? result : null;
}

function generatorBlocks(text) {
  const input = tokens(text);
  if (!input) return [];
  const blocks = [];
  for (let index = 0; index < input.length; index += 1) {
    if (input[index].type !== 'identifier' || input[index].value !== 'generator'
        || input[index + 1]?.type !== 'identifier' || input[index + 2]?.type !== '{') continue;
    let depth = 1;
    let cursor = index + 3;
    const fields = new Map();
    let invalid = false;
    while (cursor < input.length && depth > 0) {
      if (input[cursor].type === '{') depth += 1;
      else if (input[cursor].type === '}') depth -= 1;
      else if (depth === 1 && input[cursor].type === 'identifier'
          && input[cursor + 1]?.type === '=' && input[cursor + 2]?.type === 'string') {
        if (fields.has(input[cursor].value)) invalid = true;
        fields.set(input[cursor].value, input[cursor + 2].value);
        cursor += 2;
      }
      cursor += 1;
    }
    if (!invalid && depth === 0) blocks.push({ name: input[index + 1].value, fields });
    index = Math.max(index, cursor - 1);
  }
  return blocks;
}

export function prismaGeneratorRecords(files = []) {
  const records = [];
  for (const file of files) {
    const path = safePath(file.path);
    if (!path || !path.endsWith('.prisma') || typeof file.text !== 'string') continue;
    for (const block of generatorBlocks(file.text)) {
      if (block.fields.get('provider') !== 'prisma-client') continue;
      const output = block.fields.get('output');
      if (typeof output !== 'string') continue;
      const directory = safePath(posix.join(posix.dirname(path), output));
      if (!directory) continue;
      records.push({ provider: 'prisma', schemaPath: path,
        clientModule: safePath(posix.join(directory, 'client')) });
    }
  }
  return records.filter((record) => record.clientModule);
}

export function resolveGeneratedProviderImport(fromPath, specifier, records = []) {
  if (typeof specifier !== 'string' || !specifier.startsWith('.')) return null;
  const target = safePath(posix.join(posix.dirname(fromPath), specifier));
  if (!target) return { path: null, reason: 'module_path_escape' };
  const matches = records.filter((record) => record.clientModule === target);
  if (matches.length !== 1) return matches.length > 1
    ? { path: null, reason: 'module_resolution_ambiguous' } : null;
  return {
    path: null, reason: null, generatedProvider: matches[0].provider,
    providerEvidencePath: matches[0].schemaPath,
  };
}
