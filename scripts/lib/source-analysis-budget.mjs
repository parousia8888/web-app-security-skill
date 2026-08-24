const TOKEN_BUDGETS = new WeakMap();

export const DEFAULT_SOURCE_ANALYSIS_LIMITS = Object.freeze({
  maxTokensPerFile: 100000,
  maxOperationsPerFile: 2000000,
  maxOperationsTotal: 50000000,
});

const LIMIT_RANGES = Object.freeze({
  maxTokensPerFile: [1, 1000000],
  maxOperationsPerFile: [1, 100000000],
  maxOperationsTotal: [1, 1000000000],
});

export function sourceAnalysisLimits(overrides = {}) {
  const limits = { ...DEFAULT_SOURCE_ANALYSIS_LIMITS, ...overrides };
  for (const [name, [minimum, maximum]] of Object.entries(LIMIT_RANGES)) {
    if (!Number.isInteger(limits[name]) || limits[name] < minimum || limits[name] > maximum) {
      throw new Error(`${name} must be an integer from ${minimum} to ${maximum}`);
    }
  }
  return limits;
}

export class SourceAnalysisLimitError extends Error {
  constructor(code) {
    super(code);
    this.name = 'SourceAnalysisLimitError';
    this.code = code;
  }
}

export function isSourceAnalysisLimitError(error) {
  return error instanceof SourceAnalysisLimitError;
}

export function createSourceAnalysisSession(overrides = {}) {
  const limits = sourceAnalysisLimits(overrides);
  const usage = {
    filesStarted: 0,
    filesCompleted: 0,
    filesIncomplete: 0,
    tokens: 0,
    operations: 0,
    globalLimitReached: false,
  };

  return {
    limits,
    startFile() {
      usage.filesStarted += 1;
      let tokens = 0;
      let operations = 0;
      let finished = false;
      return {
        token(count = 1) {
          if (!Number.isInteger(count) || count < 0) throw new Error('token count must be a non-negative integer');
          if (tokens + count > limits.maxTokensPerFile) {
            throw new SourceAnalysisLimitError('source_token_limit');
          }
          tokens += count;
          usage.tokens += count;
        },
        operation(count = 1) {
          if (!Number.isInteger(count) || count < 0) throw new Error('operation count must be a non-negative integer');
          if (operations + count > limits.maxOperationsPerFile) {
            throw new SourceAnalysisLimitError('source_operation_limit');
          }
          if (usage.operations + count > limits.maxOperationsTotal) {
            usage.globalLimitReached = true;
            throw new SourceAnalysisLimitError('source_global_operation_limit');
          }
          operations += count;
          usage.operations += count;
        },
        finish(completed) {
          if (finished) return;
          finished = true;
          if (completed) usage.filesCompleted += 1;
          else usage.filesIncomplete += 1;
        },
      };
    },
    snapshot() {
      return {
        effectiveLimits: { ...limits },
        usage: { ...usage },
      };
    },
  };
}

export function bindAnalysisBudget(tokens, budget) {
  if (budget) TOKEN_BUDGETS.set(tokens, budget);
  return tokens;
}

export function analysisBudgetFor(tokens) {
  return TOKEN_BUDGETS.get(tokens) || null;
}

export function chargeAnalysisOperations(tokens, count = 1) {
  analysisBudgetFor(tokens)?.operation(count);
}
