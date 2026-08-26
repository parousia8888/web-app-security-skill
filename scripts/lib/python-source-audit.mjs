import {
  analysisBudgetFor, bindAnalysisBudget, chargeAnalysisOperations,
  createSourceAnalysisSession, isSourceAnalysisLimitError,
} from './source-analysis-budget.mjs';

export const PYTHON_SOURCE_RULE_IDS = [
  'python-dynamic-code-execution',
  'python-shell-command-execution',
  'python-unsafe-deserialization',
  'python-unsafe-yaml-load',
  'python-tls-verification-disabled',
  'python-framework-debug-enabled',
  'python-hardcoded-framework-secret',
  'python-cors-wildcard-with-credentials',
  'python-insecure-session-cookie-settings',
  'python-csrf-protection-disabled',
];

export const PYTHON_DEFERRED_CANDIDATES = [
  { id: 'python-cookie-defaults', reason: 'requires_framework_cookie_purpose_and_proxy_context' },
  { id: 'python-weak-hash-or-randomness', reason: 'requires_security_purpose_context' },
  { id: 'python-sensitive-value-logging', reason: 'requires_runtime_value_and_logging_context' },
  { id: 'python-generic-path-or-tempfile-use', reason: 'requires_trust_boundary_and_lifecycle_context' },
  { id: 'python-permissive-hosts', reason: 'requires_deployment_and_proxy_context' },
];

const SOURCE_EXTENSION = /\.py$/i;
const GENERATED_FILE = /(?:^|\/)(?:generated|vendor|migrations)(?:\/|$)|(?:_pb2|\.generated)\.py$/i;
const TEST_FILE = /(?:^|\/)(?:test|tests|fixtures)(?:\/|$)|(?:^|\/)(?:test_.*|.*_test)\.py$/i;
const PLACEHOLDER = /^(?:change[-_ ]?me|replace[-_ ]?me|example|placeholder|test|testing|development|dev|secret|your[-_ ].*|<.*>|\$\{.*\})$/i;
const STRING_START_AT = /(?:[rRuUbBfF]{0,2})(?:'''|"""|'|")/y;
const IDENTIFIER_AT = /[A-Za-z_]\w*/y;
const NUMBER_AT = /(?:0[xob][0-9a-f_]+|\d+(?:\.\d+)?)/iy;

export function classifyPythonSource(path) {
  if (!SOURCE_EXTENSION.test(path)) return { eligible: false, reason: 'unsupported_python_extension' };
  if (GENERATED_FILE.test(path)) return { eligible: false, reason: 'generated_or_migration_source' };
  if (TEST_FILE.test(path)) return { eligible: false, reason: 'test_or_fixture_source' };
  return { eligible: true, reason: null };
}

function stringStart(text, index) {
  STRING_START_AT.lastIndex = index;
  const match = STRING_START_AT.exec(text);
  if (!match) return null;
  const quote = /'''|"""|'|"/.exec(match[0])?.[0];
  if (!quote) return null;
  const prefix = match[0].slice(0, -quote.length);
  if (prefix && !/^(?:r|u|b|f|br|rb|fr|rf)$/i.test(prefix)) return null;
  return { prefix, quote, length: match[0].length };
}

function tokenizePythonWithBudget(text, budget) {
  const tokens = bindAnalysisBudget([], budget);
  const delimiters = [];
  let index = 0;
  let line = 1;
  const push = (type, value, start, startLine, extra = {}) => {
    budget.token();
    tokens.push({ type, value, start, line: startLine, ...extra });
  };
  while (index < text.length) {
    budget.operation();
    const character = text[index];
    if (/\s/.test(character)) {
      if (character === '\n') line += 1;
      index += 1;
      continue;
    }
    if (character === '#') {
      while (index < text.length && text[index] !== '\n') {
        budget.operation();
        index += 1;
      }
      continue;
    }
    const string = stringStart(text, index);
    if (string) {
      const start = index;
      const startLine = line;
      index += string.length;
      let value = '';
      let closed = false;
      while (index < text.length) {
        budget.operation();
        if (text.startsWith(string.quote, index)) {
          index += string.quote.length;
          closed = true;
          break;
        }
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
        value += current;
        index += 1;
      }
      if (!closed) return { tokens, error: { code: 'unterminated_python_string', line: startLine } };
      push('string', value, start, startLine, {
        prefix: string.prefix.toLowerCase(), dynamic: string.prefix.toLowerCase().includes('f'),
      });
      continue;
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
    const operator = ['**=', '//=', '>>=', '<<=', ':=', '==', '!=', '>=', '<=', '**', '//', '<<', '>>',
      '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '->'].find((candidate) =>
      text.startsWith(candidate, index));
    const value = operator || character;
    if (['(', '[', '{'].includes(value)) delimiters.push({ value, line });
    if ([')', ']', '}'].includes(value)) {
      const expected = { ')': '(', ']': '[', '}': '{' }[value];
      if (delimiters.at(-1)?.value !== expected) {
        return { tokens, error: { code: 'unbalanced_python_delimiter', line } };
      }
      delimiters.pop();
    }
    push('punct', value, index, line);
    index += value.length;
  }
  if (delimiters.length) {
    return { tokens, error: { code: 'unbalanced_python_delimiter', line: delimiters.at(-1).line } };
  }
  return { tokens, error: null };
}

export function tokenizePython(text, { analysisBudget = null, analysisLimits = {} } = {}) {
  const localSession = analysisBudget ? null : createSourceAnalysisSession(analysisLimits);
  const budget = analysisBudget || localSession.startFile();
  let completed = false;
  try {
    const result = tokenizePythonWithBudget(text, budget);
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
    if (valueAt(tokens, index) === open) depth += 1;
    if (valueAt(tokens, index) === close) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function dottedName(tokens, start, end) {
  let value = '';
  for (let index = start; index < end; index += 1) {
    chargeAnalysisOperations(tokens);
    if (tokens[index]?.type === 'identifier' || valueAt(tokens, index) === '.') value += valueAt(tokens, index);
    else break;
  }
  return value;
}

function pythonBindings(tokens) {
  const namespaces = new Map();
  const named = new Map();
  for (let index = 0; index < tokens.length; index += 1) {
    chargeAnalysisOperations(tokens);
    if (valueAt(tokens, index) === 'import' && valueAt(tokens, index - 1) !== 'from') {
      let cursor = index + 1;
      const statementLine = tokens[index].line;
      while (cursor < tokens.length && (tokens[cursor].line === statementLine
        || [',', 'as', '.'].includes(valueAt(tokens, cursor)))) {
        chargeAnalysisOperations(tokens);
        if (tokens[cursor]?.type !== 'identifier') {
          cursor += 1;
          continue;
        }
        const moduleStart = cursor;
        while (valueAt(tokens, cursor + 1) === '.' && tokens[cursor + 2]?.type === 'identifier') {
          chargeAnalysisOperations(tokens);
          cursor += 2;
        }
        const moduleName = dottedName(tokens, moduleStart, cursor + 1);
        let local = moduleName.split('.')[0];
        if (valueAt(tokens, cursor + 1) === 'as' && tokens[cursor + 2]?.type === 'identifier') {
          local = valueAt(tokens, cursor + 2);
          cursor += 2;
        }
        namespaces.set(local, moduleName);
        cursor += 1;
        if (valueAt(tokens, cursor) === ',') cursor += 1;
        else break;
      }
      continue;
    }
    if (valueAt(tokens, index) !== 'from') continue;
    let importIndex = index + 1;
    while (importIndex < tokens.length && valueAt(tokens, importIndex) !== 'import'
      && importIndex - index < 20) {
      chargeAnalysisOperations(tokens);
      importIndex += 1;
    }
    if (valueAt(tokens, importIndex) !== 'import') continue;
    const moduleName = dottedName(tokens, index + 1, importIndex);
    let cursor = importIndex + 1;
    const wrapped = valueAt(tokens, cursor) === '(';
    const end = wrapped ? matchingToken(tokens, cursor) : -1;
    if (wrapped) cursor += 1;
    while (cursor < tokens.length && (wrapped ? cursor < end : tokens[cursor].line === tokens[importIndex].line)) {
      chargeAnalysisOperations(tokens);
      if (tokens[cursor]?.type !== 'identifier') {
        cursor += 1;
        continue;
      }
      const imported = valueAt(tokens, cursor);
      let local = imported;
      if (valueAt(tokens, cursor + 1) === 'as' && tokens[cursor + 2]?.type === 'identifier') {
        local = valueAt(tokens, cursor + 2);
        cursor += 2;
      }
      named.set(local, { module: moduleName, operation: imported });
      cursor += 1;
      if (valueAt(tokens, cursor) === ',') cursor += 1;
    }
  }
  return { namespaces, named };
}

function resolvedCall(tokens, index, bindings) {
  if (tokens[index]?.type !== 'identifier') return null;
  if (valueAt(tokens, index + 1) === '(' && bindings.named.has(valueAt(tokens, index))) {
    const binding = bindings.named.get(valueAt(tokens, index));
    return { ...binding, open: index + 1 };
  }
  if (valueAt(tokens, index + 1) === '.' && tokens[index + 2]?.type === 'identifier'
      && valueAt(tokens, index + 3) === '(' && bindings.namespaces.has(valueAt(tokens, index))) {
    return { module: bindings.namespaces.get(valueAt(tokens, index)), operation: valueAt(tokens, index + 2),
      open: index + 3 };
  }
  return null;
}

function splitArguments(tokens, open, close) {
  const budget = analysisBudgetFor(tokens);
  const result = bindAnalysisBudget([], budget);
  let start = open + 1;
  const stack = [];
  for (let index = open + 1; index < close; index += 1) {
    chargeAnalysisOperations(tokens);
    const value = valueAt(tokens, index);
    if (['(', '[', '{'].includes(value)) stack.push(value);
    if ([')', ']', '}'].includes(value)) stack.pop();
    if (value === ',' && !stack.length) {
      if (start < index) result.push(bindAnalysisBudget(tokens.slice(start, index), budget));
      start = index + 1;
    }
  }
  if (start < close) result.push(bindAnalysisBudget(tokens.slice(start, close), budget));
  return result;
}

function keyword(argumentsList, name) {
  for (const argument of argumentsList) {
    chargeAnalysisOperations(argumentsList);
    if (valueAt(argument, 0) === name && valueAt(argument, 1) === '=') {
      return bindAnalysisBudget(argument.slice(2), analysisBudgetFor(argument));
    }
  }
  return null;
}

function tokenIsLiteral(token, expected) {
  if (!token) return false;
  if (['True', 'False', 'None'].includes(expected)) {
    return token.type === 'identifier' && token.value === expected;
  }
  if (/^-?(?:\d+(?:\.\d*)?|\.\d+)$/.test(expected)) {
    return token.type === 'number' && token.value === expected;
  }
  return token.type === 'string' && token.value === expected;
}

function literalIs(argument, expected) {
  if (!argument) return false;
  if (argument.length === 1) return tokenIsLiteral(argument[0], expected);
  if (valueAt(argument, 0) !== '[' || valueAt(argument, argument.length - 1) !== ']') return false;
  for (let index = 1; index < argument.length - 1; index += 1) {
    chargeAnalysisOperations(argument);
    if (argument[index].type === 'string' && argument[index].value === expected) return true;
  }
  return false;
}

function qualifiedName(argument) {
  let result = '';
  for (const token of argument || []) {
    chargeAnalysisOperations(argument);
    if (token.type === 'identifier' || token.value === '.') result += token.value;
  }
  return result;
}

function callDetails(tokens, call) {
  const close = matchingToken(tokens, call.open);
  return close < 0 ? null : { close, argumentsList: splitArguments(tokens, call.open, close) };
}

function finding(ruleId, path, token, kind, summary, evidence = {}) {
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
    remediation: 'Review the named construct and replace the unsafe API or explicit option with the framework-supported safe form.',
    retest: 'Rerun the source audit, then exercise the affected security case and the normal product journey.',
  };
}

const OUTPUT = {
  'python-dynamic-code-execution': {
    title: 'Python dynamic code execution requires input review', severity: 'high',
    text: 'Python eval or exec is called directly. Whether untrusted input reaches the call is not established.',
  },
  'python-shell-command-execution': {
    title: 'Python shell command execution requires input review', severity: 'high',
    text: 'A resolved Python process API invokes a command interpreter. Argument influence and reachability remain unknown.',
  },
  'python-unsafe-deserialization': {
    title: 'Python object deserialization requires trust review', severity: 'high',
    text: 'A resolved Pickle or Dill load API can construct Python objects. The source and trust of the bytes remain unknown.',
  },
  'python-unsafe-yaml-load': {
    title: 'Python YAML load uses an unsafe form', severity: 'high',
    text: 'A resolved PyYAML load call omits a safe loader or explicitly selects an unsafe loader. Input trust remains unknown.',
  },
  'python-tls-verification-disabled': {
    title: 'Python HTTP certificate verification is disabled', severity: 'high',
    text: 'A resolved Requests or HTTPX client call explicitly disables certificate verification. Runtime use remains unknown.',
  },
  'python-framework-debug-enabled': {
    title: 'Python Web framework debug mode is explicitly enabled', severity: 'high',
    text: 'Flask or Django debug mode is explicitly enabled in source. Whether this configuration reaches production remains unknown.',
  },
  'python-hardcoded-framework-secret': {
    title: 'Python framework secret is hard-coded in source', severity: 'high',
    text: 'A Django or Flask secret setting contains a fixed non-placeholder value. The value is redacted and deployment use is unknown.',
  },
  'python-cors-wildcard-with-credentials': {
    title: 'Python credentialed wildcard CORS requires review', severity: 'medium',
    text: 'A Python CORS configuration combines wildcard origins with credentials. Effective middleware behavior remains unknown.',
  },
  'python-insecure-session-cookie-settings': {
    title: 'Python session cookie protection is explicitly disabled', severity: 'medium',
    text: 'A supported Django or Flask setting explicitly disables Secure or HttpOnly for a session-related cookie. Deployment use remains unknown.',
  },
  'python-csrf-protection-disabled': {
    title: 'Python CSRF protection is explicitly disabled', severity: 'high',
    text: 'A supported Django or Flask construct explicitly disables or exempts CSRF protection. Route exposure and compensating controls remain unknown.',
  },
};

function inspectPythonSourceWithBudget(path, text, budget) {
  const parsed = tokenizePython(text, { analysisBudget: budget });
  if (parsed.error) return { findings: [], error: parsed.error };
  const { tokens } = parsed;
  const bindings = pythonBindings(tokens);
  const findings = [];
  const emitted = new Set();
  const flaskApps = new Set();
  const csrfProtectors = new Set();
  const add = (ruleId, token, kind, evidence = {}) => {
    const key = `${ruleId}:${token.line}:${kind}`;
    if (emitted.has(key)) return;
    emitted.add(key);
    findings.push(finding(ruleId, path, token, kind, OUTPUT[ruleId], evidence));
  };

  for (let index = 0; index < tokens.length; index += 1) {
    chargeAnalysisOperations(tokens);
    const call = resolvedCall(tokens, index, bindings);
    if (call?.module === 'flask' && call.operation === 'Flask' && valueAt(tokens, index - 1) === '='
        && tokens[index - 2]?.type === 'identifier') flaskApps.add(valueAt(tokens, index - 2));
    if (call && ['flask_wtf.csrf', 'flask_seasurf'].includes(call.module)
        && ['CSRFProtect', 'SeaSurf'].includes(call.operation) && valueAt(tokens, index - 1) === '='
        && tokens[index - 2]?.type === 'identifier') csrfProtectors.add(valueAt(tokens, index - 2));
  }

  for (let index = 0; index < tokens.length; index += 1) {
    chargeAnalysisOperations(tokens);
    const token = tokens[index];
    if (['eval', 'exec'].includes(token.value) && valueAt(tokens, index + 1) === '('
        && !bindings.named.has(token.value) && valueAt(tokens, index - 1) !== '.') {
      add('python-dynamic-code-execution', token, `${token.value}_call`);
    }

    const call = resolvedCall(tokens, index, bindings);
    const details = call ? callDetails(tokens, call) : null;
    if (call && details) {
      const shell = keyword(details.argumentsList, 'shell');
      if (call.module === 'os' && ['system', 'popen'].includes(call.operation)) {
        add('python-shell-command-execution', token, `os_${call.operation}`);
      }
      if (call.module === 'subprocess' && ['getoutput', 'getstatusoutput'].includes(call.operation)) {
        add('python-shell-command-execution', token, `subprocess_${call.operation}`);
      }
      if (call.module === 'subprocess' && ['run', 'call', 'check_call', 'check_output', 'Popen'].includes(call.operation)
          && literalIs(shell, 'True')) {
        add('python-shell-command-execution', token, `subprocess_${call.operation}_shell_true`);
      }
      if (['pickle', 'dill'].includes(call.module) && ['load', 'loads'].includes(call.operation)) {
        add('python-unsafe-deserialization', token, `${call.module}_${call.operation}`);
      }
      if (call.module === 'yaml' && call.operation === 'load') {
        const loader = keyword(details.argumentsList, 'Loader');
        const loaderName = qualifiedName(loader);
        const loaderBinding = loader?.length === 1 ? bindings.named.get(loaderName) : null;
        const loaderLeaf = loaderBinding?.module === 'yaml'
          ? loaderBinding.operation : loaderName.split('.').at(-1);
        if (loader && ['Loader', 'UnsafeLoader'].includes(loaderLeaf)) {
          add('python-unsafe-yaml-load', token, 'yaml_unsafe_loader');
        }
      }
      if (call.module === 'requests' && ['get', 'post', 'put', 'patch', 'delete', 'request', 'head', 'options'].includes(call.operation)
          && literalIs(keyword(details.argumentsList, 'verify'), 'False')) {
        add('python-tls-verification-disabled', token, `requests_${call.operation}_verify_false`);
      }
      if (call.module === 'httpx' && ['get', 'post', 'put', 'patch', 'delete', 'request', 'head', 'options', 'Client', 'AsyncClient'].includes(call.operation)
          && literalIs(keyword(details.argumentsList, 'verify'), 'False')) {
        add('python-tls-verification-disabled', token, `httpx_${call.operation}_verify_false`);
      }
      if (call.module === 'flask_cors' && call.operation === 'CORS'
          && literalIs(keyword(details.argumentsList, 'origins'), '*')
          && literalIs(keyword(details.argumentsList, 'supports_credentials'), 'True')) {
        add('python-cors-wildcard-with-credentials', token, 'flask_cors_wildcard_credentials');
      }
    }

    if (flaskApps.has(token.value) && valueAt(tokens, index + 1) === '.'
        && valueAt(tokens, index + 2) === 'run' && valueAt(tokens, index + 3) === '(') {
      const close = matchingToken(tokens, index + 3);
      const args = close > index ? splitArguments(tokens, index + 3, close) : [];
      if (literalIs(keyword(args, 'debug'), 'True')) {
        add('python-framework-debug-enabled', token, 'flask_run_debug_true');
      }
    }
    if (flaskApps.has(token.value) && valueAt(tokens, index + 1) === '.'
        && valueAt(tokens, index + 2) === 'debug' && valueAt(tokens, index + 3) === '='
        && tokenIsLiteral(tokens[index + 4], 'True')) {
      add('python-framework-debug-enabled', token, 'flask_debug_true');
    }
    if (/(?:^|\/)settings\.py$/i.test(path) && token.value === 'DEBUG'
        && valueAt(tokens, index + 1) === '=' && tokenIsLiteral(tokens[index + 2], 'True')) {
      add('python-framework-debug-enabled', token, 'django_debug_true');
    }

    if (/(?:^|\/)settings\.py$/i.test(path) && [
      'SESSION_COOKIE_SECURE', 'SESSION_COOKIE_HTTPONLY', 'CSRF_COOKIE_SECURE',
    ].includes(token.value) && valueAt(tokens, index + 1) === '='
        && tokenIsLiteral(tokens[index + 2], 'False')) {
      add('python-insecure-session-cookie-settings', token,
        `django_${token.value.toLowerCase()}_false`);
    }

    const csrfExempt = bindings.named.get(token.value);
    if (csrfExempt?.module === 'django.views.decorators.csrf'
        && csrfExempt.operation === 'csrf_exempt' && valueAt(tokens, index - 1) === '@') {
      add('python-csrf-protection-disabled', token, 'django_csrf_exempt_decorator');
    }
    if (csrfProtectors.has(token.value) && valueAt(tokens, index + 1) === '.'
        && valueAt(tokens, index + 2) === 'exempt') {
      add('python-csrf-protection-disabled', token, 'flask_csrf_exempt');
    }

    if (flaskApps.has(token.value) && valueAt(tokens, index + 1) === '.'
        && valueAt(tokens, index + 2) === 'config' && valueAt(tokens, index + 3) === '['
        && tokens[index + 4]?.type === 'string' && valueAt(tokens, index + 5) === ']'
        && valueAt(tokens, index + 6) === '=' && tokenIsLiteral(tokens[index + 7], 'False')) {
      const setting = valueAt(tokens, index + 4);
      if (['SESSION_COOKIE_SECURE', 'SESSION_COOKIE_HTTPONLY'].includes(setting)) {
        add('python-insecure-session-cookie-settings', token,
          `flask_${setting.toLowerCase()}_false`);
      }
      if (['WTF_CSRF_ENABLED', 'WTF_CSRF_CHECK_DEFAULT'].includes(setting)) {
        add('python-csrf-protection-disabled', token, `flask_${setting.toLowerCase()}_false`);
      }
    }

    if (flaskApps.has(token.value) && valueAt(tokens, index + 1) === '.'
        && valueAt(tokens, index + 2) === 'config' && valueAt(tokens, index + 3) === '.'
        && ['update', 'from_mapping'].includes(valueAt(tokens, index + 4))
        && valueAt(tokens, index + 5) === '(') {
      const close = matchingToken(tokens, index + 5);
      const args = close > index ? splitArguments(tokens, index + 5, close) : [];
      for (const setting of ['SESSION_COOKIE_SECURE', 'SESSION_COOKIE_HTTPONLY']) {
        if (literalIs(keyword(args, setting), 'False')) add('python-insecure-session-cookie-settings', token,
          `flask_${setting.toLowerCase()}_false`);
      }
      for (const setting of ['WTF_CSRF_ENABLED', 'WTF_CSRF_CHECK_DEFAULT']) {
        if (literalIs(keyword(args, setting), 'False')) add('python-csrf-protection-disabled', token,
          `flask_${setting.toLowerCase()}_false`);
      }
    }

    const staticSecret = tokens[index + 2]?.type === 'string' && !tokens[index + 2].dynamic
      ? tokens[index + 2].value : null;
    if (/(?:^|\/)settings\.py$/i.test(path) && token.value === 'SECRET_KEY'
        && valueAt(tokens, index + 1) === '=' && staticSecret != null
        && staticSecret.length >= 12 && !PLACEHOLDER.test(staticSecret)) {
      add('python-hardcoded-framework-secret', token, 'django_secret_key_literal', {
        literalRedacted: true,
        literalLengthBand: staticSecret.length < 24 ? '12-23' : staticSecret.length < 48 ? '24-47' : '48+',
      });
    }
    if (flaskApps.has(token.value) && valueAt(tokens, index + 1) === '.'
        && valueAt(tokens, index + 2) === 'secret_key' && valueAt(tokens, index + 3) === '='
        && tokens[index + 4]?.type === 'string' && !tokens[index + 4].dynamic) {
      const literal = tokens[index + 4].value;
      if (literal.length >= 12 && !PLACEHOLDER.test(literal)) {
        add('python-hardcoded-framework-secret', token, 'flask_secret_key_literal', {
          literalRedacted: true,
          literalLengthBand: literal.length < 24 ? '12-23' : literal.length < 48 ? '24-47' : '48+',
        });
      }
    }

    if (bindings.named.get(token.value)?.module === 'starlette.middleware.cors'
        && bindings.named.get(token.value)?.operation === 'CORSMiddleware'
        && valueAt(tokens, index - 1) === '(' && valueAt(tokens, index - 2) === 'add_middleware') {
      const close = matchingToken(tokens, index - 1);
      const args = close > index ? splitArguments(tokens, index - 1, close) : [];
      if (literalIs(keyword(args, 'allow_origins'), '*')
          && literalIs(keyword(args, 'allow_credentials'), 'True')) {
        add('python-cors-wildcard-with-credentials', token, 'starlette_cors_wildcard_credentials');
      }
    }
  }

  if (/(?:^|\/)settings\.py$/i.test(path)) {
    let allowAll = null;
    let credentials = false;
    for (let index = 0; index < tokens.length; index += 1) {
      chargeAnalysisOperations(tokens);
      if (tokens[index].value === 'CORS_ALLOW_ALL_ORIGINS'
          && valueAt(tokens, index + 1) === '=' && tokenIsLiteral(tokens[index + 2], 'True')) {
        allowAll = tokens[index];
      }
      if (tokens[index].value === 'CORS_ALLOW_CREDENTIALS'
          && valueAt(tokens, index + 1) === '=' && tokenIsLiteral(tokens[index + 2], 'True')) {
        credentials = true;
      }
    }
    if (allowAll && credentials) {
      add('python-cors-wildcard-with-credentials', allowAll, 'django_cors_wildcard_credentials');
    }
  }
  return { findings, error: null };
}

export function inspectPythonSource(path, text, { analysisSession = null, analysisLimits = {} } = {}) {
  const session = analysisSession || createSourceAnalysisSession(analysisLimits);
  const budget = session.startFile();
  let completed = false;
  try {
    const result = inspectPythonSourceWithBudget(path, text, budget);
    completed = result.error === null;
    return result;
  } catch (error) {
    if (isSourceAnalysisLimitError(error)) return { findings: [], error: { code: error.code, line: null } };
    throw error;
  } finally {
    budget.finish(completed);
  }
}
