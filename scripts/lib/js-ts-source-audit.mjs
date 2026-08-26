import {
  bindAnalysisBudget, chargeAnalysisOperations,
  createSourceAnalysisSession, isSourceAnalysisLimitError,
} from './source-analysis-budget.mjs';

export const JS_TS_SOURCE_RULE_IDS = [
  'js-dynamic-code-execution',
  'node-child-process-shell-execution',
  'react-dangerous-html-sink',
  'browser-html-injection-sink',
  'cors-wildcard-with-credentials',
  'node-tls-verification-disabled',
  'jwt-unsafe-verification-options',
  'hardcoded-auth-secret',
  'js-inline-session-secret',
  'js-insecure-cookie-options',
];

export const JS_TS_DEFERRED_CANDIDATES = [
  { id: 'generic-sql-string-construction', reason: 'requires_source_to_query_data_flow' },
  { id: 'generic-path-construction', reason: 'requires_trust_boundary_data_flow' },
  { id: 'logging-sensitive_named_variables', reason: 'name_does_not_prove_sensitive_runtime_value' },
  { id: 'weak_hash_or_randomness', reason: 'requires_security_purpose_context' },
  { id: 'missing_cookie_flags', reason: 'requires_framework_and_cookie_purpose_context' },
  { id: 'upload_policy_missing', reason: 'policy_may_exist_at_another_enforcement_layer' },
  { id: 'reflected_dynamic_cors_origin', reason: 'requires_callback_and_allowlist_data_flow' },
];

const SOURCE_EXTENSION = /\.(?:[cm]?[jt]sx?)$/i;
const GENERATED_FILE = /(?:^|\/)(?:generated|vendor)(?:\/|$)|(?:\.min|\.bundle|\.generated)\.[cm]?[jt]sx?$/i;
const TEST_FILE = /(?:^|\/)(?:__tests__|test|tests|fixtures)(?:\/|$)|\.(?:test|spec|stories)\.[cm]?[jt]sx?$/i;
const PLACEHOLDER = /^(?:change[-_ ]?me|replace[-_ ]?me|example|placeholder|test|development|dev|secret|your[-_ ].*|<.*>|\$\{.*\})$/i;
const IDENTIFIER_AT = /[A-Za-z_$][\w$]*/y;
const NUMBER_AT = /(?:0[xob][0-9a-f]+|\d+(?:\.\d+)?)/iy;

export function classifyJsTsSource(path) {
  if (!SOURCE_EXTENSION.test(path)) return { eligible: false, reason: 'unsupported_js_ts_extension' };
  if (GENERATED_FILE.test(path)) return { eligible: false, reason: 'generated_or_minified_source' };
  if (TEST_FILE.test(path)) return { eligible: false, reason: 'test_or_fixture_source' };
  return { eligible: true, reason: null };
}

function regexMayStart(previous) {
  if (!previous) return true;
  if (previous.type === 'punct') {
    return ['(', '[', '{', '=', ':', ',', ';', '!', '?', '&&', '||', '??', '=>', '+', '-', '*', '/',
      '%', '&', '|', '^', '~', '<', '>', '==', '===', '!=', '!==', '<=', '>=', '+='].includes(previous.value);
  }
  return previous.type === 'identifier'
    && ['return', 'throw', 'case', 'default', 'delete', 'void', 'typeof', 'instanceof', 'in', 'of',
      'yield', 'await', 'from'].includes(previous.value);
}

function jsxTagMayStart(text, index, previous, fromText) {
  const next = text[index + 1] || '';
  if (fromText) return next === '/' || next === '>' || /[A-Za-z_$]/.test(next);
  return regexMayStart(previous) && (next === '>' || /[A-Za-z_$]/.test(next));
}

function tokenizeJsTsWithBudget(text, jsx, budget) {
  const tokens = bindAnalysisBudget([], budget);
  let index = 0;
  let line = 1;
  const templateStack = [];
  let jsxMode = 'code';
  let pendingJsxClosing = false;
  let pendingJsxReturnMode = 'code';
  const jsxElements = [];
  let jsxExpressionDepth = 0;
  let jsxExpressionReturnMode = 'text';
  const push = (type, value, start, startLine) => {
    budget.token();
    tokens.push({ type, value, start, line: startLine });
  };
  while (index < text.length) {
    budget.operation();
    const character = text[index];
    const template = templateStack.at(-1);
    if (template && !template.inExpression) {
      if (character === '\\') {
        if (text[index + 1] === '\n') line += 1;
        index += Math.min(2, text.length - index);
        continue;
      }
      if (character === '`') {
        templateStack.pop();
        index += 1;
        continue;
      }
      if (character === '$' && text[index + 1] === '{') {
        template.inExpression = true;
        template.expressionDepth = 1;
        push('punct', '{', index + 1, line);
        if (jsx && jsxExpressionDepth > 0) jsxExpressionDepth += 1;
        index += 2;
        continue;
      }
      if (character === '\n') line += 1;
      index += 1;
      continue;
    }
    if (jsx && jsxMode === 'text') {
      if (character === '<' && jsxTagMayStart(text, index, tokens.at(-1), true)) {
        push('punct', '<', index, line);
        pendingJsxClosing = text[index + 1] === '/';
        pendingJsxReturnMode = 'text';
        jsxMode = 'tag';
        index += 1;
        continue;
      }
      if (character === '{') {
        push('punct', '{', index, line);
        jsxExpressionDepth = 1;
        jsxExpressionReturnMode = 'text';
        jsxMode = 'code';
        index += 1;
        continue;
      }
      if (character === '\n') line += 1;
      index += 1;
      continue;
    }
    if (jsx && jsxMode === 'tag' && character === '{') {
      push('punct', '{', index, line);
      jsxExpressionDepth = 1;
      jsxExpressionReturnMode = 'tag';
      jsxMode = 'code';
      index += 1;
      continue;
    }
    if (jsx && jsxMode === 'code' && character === '<'
        && jsxTagMayStart(text, index, tokens.at(-1), false)) {
      push('punct', '<', index, line);
      pendingJsxClosing = false;
      pendingJsxReturnMode = 'code';
      jsxMode = 'tag';
      index += 1;
      continue;
    }
    if (/\s/.test(character)) {
      if (character === '\n') line += 1;
      index += 1;
      continue;
    }
    if (character === '/' && text[index + 1] === '/') {
      index += 2;
      while (index < text.length && text[index] !== '\n') {
        budget.operation();
        index += 1;
      }
      continue;
    }
    if (character === '/' && text[index + 1] === '*') {
      const startLine = line;
      index += 2;
      let closed = false;
      while (index < text.length) {
        budget.operation();
        if (text[index] === '\n') line += 1;
        if (text[index] === '*' && text[index + 1] === '/') {
          index += 2;
          closed = true;
          break;
        }
        index += 1;
      }
      if (!closed) return { tokens, error: { code: 'unterminated_block_comment', line: startLine } };
      continue;
    }
    if (character === '`') {
      push('template', '<template-literal>', index, line);
      templateStack.push({ startLine: line, inExpression: false, expressionDepth: 0 });
      index += 1;
      continue;
    }
    if ((character === "'" || character === '"') && regexMayStart(tokens.at(-1))) {
      const quote = character;
      const start = index;
      const startLine = line;
      index += 1;
      let value = '';
      let closed = false;
      while (index < text.length) {
        budget.operation();
        const current = text[index];
        if (current === '\n') line += 1;
        if (current === '\\') {
          value += current;
          if (index + 1 < text.length) {
            value += text[index + 1];
            if (text[index + 1] === '\n') line += 1;
            index += 2;
          } else index += 1;
          continue;
        }
        if (current === quote) {
          index += 1;
          closed = true;
          break;
        }
        value += current;
        index += 1;
      }
      if (!closed) return { tokens, error: { code: 'unterminated_string_literal', line: startLine } };
      push('string', value, start, startLine);
      continue;
    }
    if (character === '/' && regexMayStart(tokens.at(-1))) {
      const start = index;
      const startLine = line;
      index += 1;
      let inClass = false;
      let closed = false;
      while (index < text.length) {
        budget.operation();
        const current = text[index];
        if (current === '\n') break;
        if (current === '\\') {
          index += 2;
          continue;
        }
        if (current === '[') inClass = true;
        if (current === ']') inClass = false;
        if (current === '/' && !inClass) {
          index += 1;
          while (/[a-z]/i.test(text[index] || '')) {
            budget.operation();
            index += 1;
          }
          closed = true;
          break;
        }
        index += 1;
      }
      if (closed) {
        push('regex', '<regular-expression>', start, startLine);
        continue;
      }
      index = start;
    }
    IDENTIFIER_AT.lastIndex = index;
    const identifier = IDENTIFIER_AT.exec(text);
    if (identifier) {
      push('identifier', identifier[0], index, line);
      index += identifier[0].length;
      continue;
    }
    NUMBER_AT.lastIndex = index;
    const number = NUMBER_AT.exec(text);
    if (number) {
      push('number', number[0], index, line);
      index += number[0].length;
      continue;
    }
    const operator = ['===', '!==', '>>>', '=>', '==', '!=', '>=', '<=', '&&', '||', '?.', '??', '**', '+=']
      .find((candidate) => text.startsWith(candidate, index));
    const value = operator || character;
    push('punct', value, index, line);
    index += value.length;
    const activeTemplate = templateStack.at(-1);
    if (activeTemplate?.inExpression) {
      if (value === '{') activeTemplate.expressionDepth += 1;
      if (value === '}') {
        activeTemplate.expressionDepth -= 1;
        if (activeTemplate.expressionDepth === 0) activeTemplate.inExpression = false;
      }
    }
    if (jsx && jsxMode === 'tag' && value === '>') {
      if (pendingJsxClosing) {
        const element = jsxElements.pop();
        jsxMode = element?.returnMode || 'code';
      } else if (valueAt(tokens, tokens.length - 2) === '/') {
        jsxMode = pendingJsxReturnMode;
      } else {
        jsxElements.push({ returnMode: pendingJsxReturnMode });
        jsxMode = 'text';
      }
      pendingJsxClosing = false;
      continue;
    }
    if (jsx && jsxExpressionDepth > 0) {
      if (value === '{') jsxExpressionDepth += 1;
      if (value === '}') {
        jsxExpressionDepth -= 1;
        if (jsxExpressionDepth === 0) jsxMode = jsxExpressionReturnMode;
      }
    }
  }
  if (templateStack.length) {
    return { tokens, error: { code: 'unterminated_string_literal', line: templateStack.at(-1).startLine } };
  }
  return { tokens, error: null };
}

export function tokenizeJsTs(text, { jsx = false, analysisBudget = null, analysisLimits = {} } = {}) {
  const localSession = analysisBudget ? null : createSourceAnalysisSession(analysisLimits);
  const budget = analysisBudget || localSession.startFile();
  let completed = false;
  try {
    const result = tokenizeJsTsWithBudget(text, jsx, budget);
    completed = result.error === null;
    return result;
  } catch (error) {
    if (isSourceAnalysisLimitError(error)) return { tokens: [], error: { code: error.code, line: null } };
    throw error;
  } finally {
    if (localSession) budget.finish(completed);
  }
}

const valueAt = (tokens, index) => tokens[index]?.value;

function matchingToken(tokens, start, open = '(', close = ')') {
  let depth = 0;
  for (let index = start; index < tokens.length; index += 1) {
    chargeAnalysisOperations(tokens);
    if (tokens[index].value === open) depth += 1;
    if (tokens[index].value === close) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function moduleBindings(tokens, moduleNames) {
  const namespaces = new Set();
  const named = new Map();
  for (let index = 0; index < tokens.length; index += 1) {
    chargeAnalysisOperations(tokens);
    if (tokens[index].type !== 'string' || !moduleNames.has(tokens[index].value)) continue;
    if (valueAt(tokens, index - 1) === '(' && valueAt(tokens, index - 2) === 'require') {
      if (valueAt(tokens, index + 1) !== ')') continue;
      if (valueAt(tokens, index - 3) === '=') namespaces.add(valueAt(tokens, index - 4));
      if (valueAt(tokens, index - 3) === '=' && valueAt(tokens, index - 4) === '}') {
        let cursor = index - 5;
        while (cursor >= 0 && valueAt(tokens, cursor) !== '{') {
          chargeAnalysisOperations(tokens);
          cursor -= 1;
        }
        for (let item = cursor + 1; item < index - 4; item += 1) {
          chargeAnalysisOperations(tokens);
          const imported = valueAt(tokens, item);
          if (tokens[item]?.type !== 'identifier') continue;
          if (valueAt(tokens, item + 1) === ':') {
            named.set(imported, valueAt(tokens, item + 2));
            item += 2;
          } else if (valueAt(tokens, item - 1) !== ':') named.set(imported, imported);
        }
      }
      continue;
    }
    if (valueAt(tokens, index - 1) !== 'from') continue;
    let cursor = index - 2;
    while (cursor >= 0 && valueAt(tokens, cursor) !== 'import' && index - cursor < 40) {
      chargeAnalysisOperations(tokens);
      cursor -= 1;
    }
    if (cursor < 0 || valueAt(tokens, cursor) !== 'import') continue;
    if (valueAt(tokens, cursor + 1) === '*') namespaces.add(valueAt(tokens, cursor + 3));
    else if (valueAt(tokens, cursor + 1) === '{') {
      for (let item = cursor + 2; item < index - 1; item += 1) {
        chargeAnalysisOperations(tokens);
        const imported = valueAt(tokens, item);
        if (tokens[item]?.type !== 'identifier') continue;
        if (valueAt(tokens, item + 1) === 'as') {
          named.set(imported, valueAt(tokens, item + 2));
          item += 2;
        } else if (valueAt(tokens, item - 1) !== 'as') named.set(imported, imported);
      }
    } else if (tokens[cursor + 1]?.type === 'identifier') namespaces.add(valueAt(tokens, cursor + 1));
  }
  return { namespaces, named };
}

function callOperation(tokens, index, bindings) {
  if (valueAt(tokens, index + 1) === '(') {
    for (const [operation, local] of bindings.named) {
      chargeAnalysisOperations(tokens);
      if (tokens[index].value === local) return operation;
    }
  }
  if (valueAt(tokens, index + 1) === '.' && valueAt(tokens, index + 3) === '('
      && bindings.namespaces.has(tokens[index].value)) return valueAt(tokens, index + 2);
  return null;
}

function objectBounds(tokens, propertyIndex) {
  let depth = 0;
  for (let start = propertyIndex - 1; start >= 0; start -= 1) {
    chargeAnalysisOperations(tokens);
    if (valueAt(tokens, start) === '}') depth += 1;
    if (valueAt(tokens, start) === '{') {
      if (depth === 0) {
        const end = matchingToken(tokens, start, '{', '}');
        return end >= propertyIndex ? [start, end] : null;
      }
      depth -= 1;
    }
  }
  return null;
}

function propertyHas(tokens, start, end, name, expected, type = null, targetDepth = 0) {
  let depth = 0;
  for (let index = start + 1; index < end - 1; index += 1) {
    chargeAnalysisOperations(tokens);
    if (['{', '[', '('].includes(valueAt(tokens, index))) depth += 1;
    if (['}', ']', ')'].includes(valueAt(tokens, index))) depth -= 1;
    if (depth === targetDepth && valueAt(tokens, index) === name && valueAt(tokens, index + 1) === ':'
        && valueAt(tokens, index + 2) === expected
        && (!type || tokens[index + 2]?.type === type)) return true;
  }
  return false;
}

function argumentRanges(tokens, open, close) {
  const ranges = [];
  let start = open + 1;
  const stack = [];
  for (let index = open + 1; index < close; index += 1) {
    chargeAnalysisOperations(tokens);
    const value = valueAt(tokens, index);
    if (['(', '[', '{'].includes(value)) stack.push(value);
    if ([')', ']', '}'].includes(value)) stack.pop();
    if (value === ',' && !stack.length) {
      ranges.push([start, index]);
      start = index + 1;
    }
  }
  if (start < close) ranges.push([start, close]);
  return ranges;
}

function objectArgument(tokens, open, close, position) {
  const range = argumentRanges(tokens, open, close)[position];
  if (!range || valueAt(tokens, range[0]) !== '{') return null;
  const end = matchingToken(tokens, range[0], '{', '}');
  return end === range[1] - 1 ? [range[0], end] : null;
}

function propertyToken(tokens, start, end, name, targetDepth = 0) {
  let depth = 0;
  for (let index = start + 1; index < end; index += 1) {
    chargeAnalysisOperations(tokens);
    const value = valueAt(tokens, index);
    if (depth === targetDepth && value === name && valueAt(tokens, index + 1) === ':') return index;
    if (['{', '[', '('].includes(value)) depth += 1;
    if (['}', ']', ')'].includes(value)) depth -= 1;
  }
  return -1;
}

function nestedObject(tokens, start, end, name, targetDepth = 0) {
  const property = propertyToken(tokens, start, end, name, targetDepth);
  const open = property >= 0 && valueAt(tokens, property + 2) === '{' ? property + 2 : -1;
  const close = open >= 0 ? matchingToken(tokens, open, '{', '}') : -1;
  return close > open ? [open, close] : null;
}

function unsafeCookieProperty(tokens, bounds) {
  if (!bounds) return null;
  for (const name of ['httpOnly', 'secure']) {
    const property = propertyToken(tokens, bounds[0], bounds[1], name);
    if (property >= 0 && valueAt(tokens, property + 2) === 'false') return { token: tokens[property], name };
  }
  return null;
}

function namedBindingLocal(bindings, operation) {
  return bindings.named.get(operation) || null;
}

function finding(ruleId, path, token, kind, summary, evidence, remediation, retest) {
  const discriminator = `${path}:${token.line}:${kind}`;
  return {
    ruleId,
    title: summary.title,
    severity: summary.severity,
    state: 'suspected',
    discriminator,
    summary: summary.text,
    location: { path, line: token.line },
    evidence: { subject: discriminator, line: token.line, construct: kind, ...evidence },
    remediation,
    retest,
  };
}

const OUTPUT = {
  'js-dynamic-code-execution': {
    title: 'JavaScript dynamic code execution requires review', severity: 'high',
    text: 'Executable code is constructed at runtime. Input influence and reachability are not established by this source lead.',
  },
  'node-child-process-shell-execution': {
    title: 'Node.js shell execution requires input-flow review', severity: 'high',
    text: 'A Node child-process API invokes a command interpreter. The audit has not proved that untrusted input reaches it.',
  },
  'react-dangerous-html-sink': {
    title: 'React raw HTML rendering requires trust review', severity: 'medium',
    text: 'React raw HTML rendering is present. Whether the rendered value is attacker-controlled or sanitized remains unknown.',
  },
  'browser-html-injection-sink': {
    title: 'Browser HTML injection sink requires trust review', severity: 'medium',
    text: 'Code writes or parses HTML through a browser sink. The source of that HTML and any sanitization remain unknown.',
  },
  'cors-wildcard-with-credentials': {
    title: 'Credentialed wildcard CORS configuration requires review', severity: 'medium',
    text: 'One configuration object combines wildcard origin access with credentials. Runtime middleware behavior still requires confirmation.',
  },
  'node-tls-verification-disabled': {
    title: 'TLS certificate verification is explicitly disabled', severity: 'high',
    text: 'Source code explicitly disables a Node.js TLS certificate check. The affected client path and environment remain to be confirmed.',
  },
  'jwt-unsafe-verification-options': {
    title: 'JWT verification uses an unsafe explicit option', severity: 'high',
    text: 'A jsonwebtoken verification call explicitly accepts an unsafe algorithm or ignores token expiry. Runtime use remains to be confirmed.',
  },
  'hardcoded-auth-secret': {
    title: 'Authentication secret is hard-coded in source', severity: 'high',
    text: 'A security-named variable is assigned a non-placeholder string. The value is redacted and whether it is deployed remains unknown.',
  },
  'js-inline-session-secret': {
    title: 'Session or token signing secret is inline in framework configuration', severity: 'high',
    text: 'A recognized session or JWT configuration receives a fixed secret literal. The value is redacted and deployment use remains unknown.',
  },
  'js-insecure-cookie-options': {
    title: 'Session cookie protection is explicitly disabled', severity: 'medium',
    text: 'A recognized session or cookie API explicitly disables Secure or HttpOnly. Runtime transport and deployment use remain unknown.',
  },
};

function inspectJsTsSourceWithBudget(path, text, budget) {
  const parsed = tokenizeJsTs(text, {
    jsx: /\.[cm]?[jt]sx$/i.test(path), analysisBudget: budget,
  });
  if (parsed.error) return { findings: [], error: parsed.error };
  const { tokens } = parsed;
  const findings = [];
  const emitted = new Set();
  const add = (ruleId, token, kind, evidence = {}) => {
    const key = `${ruleId}:${token.line}:${kind}`;
    if (emitted.has(key)) return;
    emitted.add(key);
    findings.push(finding(
      ruleId, path, token, kind, OUTPUT[ruleId], evidence,
      'Review the named construct, remove the unsafe option or keep untrusted data away from the sink using the framework-supported safe API.',
      'Rerun the source audit, then exercise the affected security case and the normal product journey.',
    ));
  };

  const childProcess = moduleBindings(tokens, new Set(['child_process', 'node:child_process']));
  const jsonwebtoken = moduleBindings(tokens, new Set(['jsonwebtoken']));
  const expressSession = moduleBindings(tokens, new Set(['express-session']));
  const nextAuth = moduleBindings(tokens, new Set(['next-auth', '@auth/core']));
  const nestJwt = moduleBindings(tokens, new Set(['@nestjs/jwt']));
  const cookieModule = moduleBindings(tokens, new Set(['cookie']));
  const cookiesNext = moduleBindings(tokens, new Set(['cookies-next']));
  for (let index = 0; index < tokens.length; index += 1) {
    chargeAnalysisOperations(tokens);
    const token = tokens[index];
    if ((token.value === 'eval' && valueAt(tokens, index + 1) === '(')
        || (token.value === 'Function' && valueAt(tokens, index + 1) === '('
          && valueAt(tokens, index - 1) === 'new')) {
      add('js-dynamic-code-execution', token, token.value === 'eval' ? 'eval_call' : 'function_constructor');
    }

    const operation = callOperation(tokens, index, childProcess);
    if (['exec', 'execSync'].includes(operation)) {
      add('node-child-process-shell-execution', token, `child_process_${operation}`);
    } else if (['spawn', 'spawnSync', 'execFile', 'execFileSync'].includes(operation)) {
      const open = valueAt(tokens, index + 1) === '(' ? index + 1 : index + 3;
      const close = matchingToken(tokens, open);
      if (close > open && propertyHas(tokens, open, close, 'shell', 'true', null, 1)) {
        add('node-child-process-shell-execution', token, `child_process_${operation}_shell_true`);
      }
    }

    if (token.value === 'dangerouslySetInnerHTML'
        && tokens.slice(index + 1, index + 14).some((item) => item.value === '__html')) {
      add('react-dangerous-html-sink', token, 'dangerously_set_inner_html');
    }
    if (valueAt(tokens, index - 1) === '.' && ['innerHTML', 'outerHTML'].includes(token.value)
        && ['=', '+='].includes(valueAt(tokens, index + 1))) {
      const operationKind = valueAt(tokens, index + 1) === '+=' ? 'append_assignment' : 'assignment';
      add('browser-html-injection-sink', token, `${token.value}_${operationKind}`);
    }
    if (valueAt(tokens, index - 1) === '.' && token.value === 'insertAdjacentHTML'
        && valueAt(tokens, index + 1) === '(') {
      add('browser-html-injection-sink', token, 'insert_adjacent_html_call');
    }
    if (token.value === 'document' && valueAt(tokens, index + 1) === '.'
        && ['write', 'writeln'].includes(valueAt(tokens, index + 2))
        && valueAt(tokens, index + 3) === '(') {
      add('browser-html-injection-sink', token, `document_${valueAt(tokens, index + 2)}_call`);
    }
    if (token.value === 'origin' && valueAt(tokens, index + 1) === ':'
        && tokens[index + 2]?.type === 'string' && valueAt(tokens, index + 2) === '*') {
      const bounds = objectBounds(tokens, index);
      if (bounds && propertyHas(tokens, bounds[0], bounds[1], 'credentials', 'true')) {
        add('cors-wildcard-with-credentials', token, 'cors_origin_wildcard_credentials_true');
      }
    }
    if (token.value === 'rejectUnauthorized' && valueAt(tokens, index + 1) === ':'
        && valueAt(tokens, index + 2) === 'false') {
      add('node-tls-verification-disabled', token, 'reject_unauthorized_false');
    }
    if (token.value === 'NODE_TLS_REJECT_UNAUTHORIZED' && valueAt(tokens, index + 1) === '='
        && tokens[index + 2]?.type === 'string' && valueAt(tokens, index + 2) === '0') {
      add('node-tls-verification-disabled', token, 'node_tls_reject_unauthorized_zero');
    }

    const jwtOperation = callOperation(tokens, index, jsonwebtoken);
    if (jwtOperation === 'verify') {
      const open = valueAt(tokens, index + 1) === '(' ? index + 1 : index + 3;
      const close = matchingToken(tokens, open);
      if (close > open) {
        const unsafeExpiry = propertyHas(tokens, open, close, 'ignoreExpiration', 'true', null, 1);
        let unsafeNone = false;
        for (let cursor = open; cursor < close - 3; cursor += 1) {
          chargeAnalysisOperations(tokens);
          if (valueAt(tokens, cursor) !== 'algorithms' || valueAt(tokens, cursor + 1) !== ':') continue;
          const arrayStart = cursor + 2;
          const arrayEnd = valueAt(tokens, arrayStart) === '[' ? matchingToken(tokens, arrayStart, '[', ']') : -1;
          if (arrayEnd > arrayStart) {
            for (let item = arrayStart + 1; item < arrayEnd; item += 1) {
              chargeAnalysisOperations(tokens);
              if (tokens[item].type === 'string' && tokens[item].value.toLowerCase() === 'none') {
                unsafeNone = true;
                break;
              }
            }
          }
        }
        if (unsafeExpiry || unsafeNone) add('jwt-unsafe-verification-options', token,
          unsafeNone ? 'jwt_none_algorithm' : 'jwt_ignore_expiration');
      }
    }

    const normalizedName = token.value.replace(/[_$-]/g, '').toLowerCase();
    const secretName = /^(?:jwt|session|auth|cookie)(?:secret|key)$/.test(normalizedName)
      || /^(?:secret|key)(?:jwt|session|auth|cookie)$/.test(normalizedName);
    if (secretName && ['=', ':'].includes(valueAt(tokens, index + 1))
        && tokens[index + 2]?.type === 'string') {
      const literal = valueAt(tokens, index + 2);
      if (literal.length >= 12 && !PLACEHOLDER.test(literal)) {
        add('hardcoded-auth-secret', token, 'security_named_literal_assignment', {
          literalRedacted: true,
          literalLengthBand: literal.length < 24 ? '12-23' : literal.length < 48 ? '24-47' : '48+',
        });
      }
    }

    let frameworkOptions = null;
    let frameworkKind = null;
    if (valueAt(tokens, index + 1) === '('
        && (expressSession.namespaces.has(token.value) || nextAuth.namespaces.has(token.value))) {
      const close = matchingToken(tokens, index + 1);
      frameworkOptions = close > index ? objectArgument(tokens, index + 1, close, 0) : null;
      frameworkKind = expressSession.namespaces.has(token.value) ? 'express_session' : 'next_auth';
    }
    const jwtModuleLocal = namedBindingLocal(nestJwt, 'JwtModule');
    if (jwtModuleLocal === token.value && valueAt(tokens, index + 1) === '.'
        && valueAt(tokens, index + 2) === 'register' && valueAt(tokens, index + 3) === '(') {
      const close = matchingToken(tokens, index + 3);
      frameworkOptions = close > index ? objectArgument(tokens, index + 3, close, 0) : null;
      frameworkKind = 'nest_jwt_register';
    }
    if (frameworkOptions) {
      const secretProperty = propertyToken(tokens, frameworkOptions[0], frameworkOptions[1], 'secret');
      const literalToken = secretProperty >= 0 ? tokens[secretProperty + 2] : null;
      if (literalToken?.type === 'string' && literalToken.value.length >= 12
          && !PLACEHOLDER.test(literalToken.value)) {
        add('js-inline-session-secret', tokens[secretProperty], `${frameworkKind}_secret_literal`, {
          literalRedacted: true,
          literalLengthBand: literalToken.value.length < 24 ? '12-23'
            : literalToken.value.length < 48 ? '24-47' : '48+',
        });
      }
      if (frameworkKind === 'express_session') {
        const unsafe = unsafeCookieProperty(tokens,
          nestedObject(tokens, frameworkOptions[0], frameworkOptions[1], 'cookie'));
        if (unsafe) add('js-insecure-cookie-options', unsafe.token,
          `express_session_cookie_${unsafe.name}_false`);
      }
      if (frameworkKind === 'next_auth') {
        const cookies = nestedObject(tokens, frameworkOptions[0], frameworkOptions[1], 'cookies');
        if (cookies) {
          for (let cursor = cookies[0] + 1; cursor < cookies[1]; cursor += 1) {
            chargeAnalysisOperations(tokens);
            if (!['httpOnly', 'secure'].includes(valueAt(tokens, cursor))
                || valueAt(tokens, cursor + 1) !== ':' || valueAt(tokens, cursor + 2) !== 'false') continue;
            add('js-insecure-cookie-options', tokens[cursor],
              `next_auth_cookie_${valueAt(tokens, cursor)}_false`);
          }
        }
      }
    }

    let cookieOptions = null;
    let cookieKind = null;
    if (['res', 'response'].includes(token.value) && valueAt(tokens, index + 1) === '.'
        && valueAt(tokens, index + 2) === 'cookie' && valueAt(tokens, index + 3) === '(') {
      const close = matchingToken(tokens, index + 3);
      cookieOptions = close > index ? objectArgument(tokens, index + 3, close, 2) : null;
      cookieKind = 'express_response_cookie';
    }
    if (cookieModule.namespaces.has(token.value) && valueAt(tokens, index + 1) === '.'
        && valueAt(tokens, index + 2) === 'serialize' && valueAt(tokens, index + 3) === '(') {
      const close = matchingToken(tokens, index + 3);
      cookieOptions = close > index ? objectArgument(tokens, index + 3, close, 2) : null;
      cookieKind = 'cookie_serialize';
    }
    if (namedBindingLocal(cookiesNext, 'setCookie') === token.value && valueAt(tokens, index + 1) === '(') {
      const close = matchingToken(tokens, index + 1);
      cookieOptions = close > index ? objectArgument(tokens, index + 1, close, 2) : null;
      cookieKind = 'cookies_next_set_cookie';
    }
    const unsafeCookie = unsafeCookieProperty(tokens, cookieOptions);
    if (unsafeCookie) add('js-insecure-cookie-options', unsafeCookie.token,
      `${cookieKind}_${unsafeCookie.name}_false`);
  }
  return { findings, error: null };
}

export function inspectJsTsSource(path, text, { analysisSession = null, analysisLimits = {} } = {}) {
  const session = analysisSession || createSourceAnalysisSession(analysisLimits);
  const budget = session.startFile();
  let completed = false;
  try {
    const result = inspectJsTsSourceWithBudget(path, text, budget);
    completed = result.error === null;
    return result;
  } catch (error) {
    if (isSourceAnalysisLimitError(error)) return { findings: [], error: { code: error.code, line: null } };
    throw error;
  } finally {
    budget.finish(completed);
  }
}
