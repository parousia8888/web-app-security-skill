import { SOURCE_RULE_REGISTRY, runtimeRule } from './source-rule-registry.mjs';

export const EXTERNAL_ADAPTER_TIMEOUT_SECONDS = 120;
export const SUPPORTED_EXTERNAL_ADAPTERS = ['checkov', 'gitleaks', 'opengrep', 'osv'];
export const DEEP_PROFILE_ADAPTERS = ['builtin', ...SUPPORTED_EXTERNAL_ADAPTERS];

const checkovRegistry = SOURCE_RULE_REGISTRY.filter((rule) => rule.adapter.id === 'checkov');
const gitleaksRegistry = SOURCE_RULE_REGISTRY.filter((rule) => rule.adapter.id === 'gitleaks');
const opengrepRegistry = SOURCE_RULE_REGISTRY.filter((rule) => rule.adapter.id === 'opengrep');
const osvRegistry = SOURCE_RULE_REGISTRY.filter((rule) => rule.adapter.id === 'osv');
export const CHECKOV_ADAPTER = {
  id: checkovRegistry[0].adapter.id,
  version: checkovRegistry[0].adapter.version,
  maturity: checkovRegistry[0].adapter.maturity,
};

export const CHECKOV_RULES = checkovRegistry.map(runtimeRule);

export const GITLEAKS_ADAPTER = {
  id: gitleaksRegistry[0].adapter.id,
  version: gitleaksRegistry[0].adapter.version,
  maturity: gitleaksRegistry[0].adapter.maturity,
};

export const GITLEAKS_RULES = gitleaksRegistry.map(runtimeRule);

export const OPENGREP_ADAPTER = {
  id: opengrepRegistry[0].adapter.id,
  version: opengrepRegistry[0].adapter.version,
  maturity: opengrepRegistry[0].adapter.maturity,
};

export const OPENGREP_RULES = opengrepRegistry.map(runtimeRule);
export const OPENGREP_RULE_ID_MAP = new Map(opengrepRegistry.map((rule) => [
  rule.detection.externalRuleId, rule.id,
]));
export const OPENGREP_RULESET = {
  relativePath: 'rules/opengrep-source.yml',
  sha256: '6e4582c6579597a5b4a62fb2f7360609bb295bd14baa450317ae9b579a65ed4d',
};

export const OSV_ADAPTER = {
  id: osvRegistry[0].adapter.id,
  version: osvRegistry[0].adapter.version,
  maturity: osvRegistry[0].adapter.maturity,
};

export const OSV_RULES = osvRegistry.map(runtimeRule);

export function adapterDefinitions(selected = ['builtin']) {
  const definitions = [];
  if (selected.includes('checkov')) definitions.push({ ...CHECKOV_ADAPTER, rules: CHECKOV_RULES });
  if (selected.includes('gitleaks')) definitions.push({ ...GITLEAKS_ADAPTER, rules: GITLEAKS_RULES });
  if (selected.includes('opengrep')) definitions.push({ ...OPENGREP_ADAPTER, rules: OPENGREP_RULES });
  if (selected.includes('osv')) definitions.push({ ...OSV_ADAPTER, rules: OSV_RULES });
  return definitions;
}

export function parseAdapterSelection(values = []) {
  const requested = values.length ? values : ['builtin'];
  const expanded = requested.flatMap((value) => value.split(',')).map((value) => value.trim()).filter(Boolean);
  const selected = new Set();
  for (const value of expanded) {
    if (value === 'all') {
      selected.add('builtin');
      for (const adapter of SUPPORTED_EXTERNAL_ADAPTERS) selected.add(adapter);
    } else if (value === 'osv-scanner') {
      selected.add('osv');
    } else if (value === 'builtin' || SUPPORTED_EXTERNAL_ADAPTERS.includes(value)) {
      selected.add(value);
    } else {
      throw new Error(`unsupported adapter ${value}; use builtin, checkov, gitleaks, opengrep, osv, or all`);
    }
  }
  if (!selected.size) throw new Error('at least one adapter is required');
  return ['builtin', ...SUPPORTED_EXTERNAL_ADAPTERS].filter((value) => selected.has(value));
}

export function resolveAdapterSelection(values = [], profile = null) {
  if (profile === null) return parseAdapterSelection(values);
  if (values.length) throw new Error('--profile cannot be combined with --adapter');
  if (profile !== 'deep') throw new Error(`unsupported profile ${profile}; use deep`);
  return [...DEEP_PROFILE_ADAPTERS];
}

export function parseAdapterTimeout(value = EXTERNAL_ADAPTER_TIMEOUT_SECONDS) {
  const timeout = Number(value);
  if (!Number.isInteger(timeout) || timeout < 1 || timeout > 600) {
    throw new Error('adapter timeout must be an integer from 1 to 600 seconds');
  }
  return timeout;
}
