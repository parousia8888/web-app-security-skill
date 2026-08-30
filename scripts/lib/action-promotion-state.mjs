const SHA1 = /^[a-f0-9]{40}$/;
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

export function validateActionPromotionState(state) {
  const errors = [];
  const published = state?.publishedRelease || {};
  const stable = state?.stableAction || {};
  const promotion = stable.promotion || {};
  if (stable.tag !== 'v1') errors.push('stable Action tag must be v1');
  if (!SHA1.test(stable.sourceCommit || '')) errors.push('stable Action source commit is invalid');
  if (!['final', 'pending'].includes(promotion.state)) {
    errors.push('stable Action promotion state must be final or pending');
  } else if (promotion.state === 'final') {
    for (const key of ['version', 'expectedSourceCommit', 'priorTagObject']) {
      if (key in promotion) errors.push(`final promotion must clear ${key}`);
    }
  } else {
    if (!SEMVER.test(promotion.version || '') || promotion.version !== published.version) {
      errors.push('pending promotion version must equal the published release version');
    }
    if (!SHA1.test(promotion.expectedSourceCommit || '')
        || promotion.expectedSourceCommit !== published.sourceCommit) {
      errors.push('pending promotion source must equal the published release source commit');
    }
    if (!SHA1.test(promotion.priorTagObject || '')) {
      errors.push('pending promotion prior tag object is invalid');
    }
  }
  return errors;
}

export function beginActionPromotion(state, input) {
  const currentErrors = validateActionPromotionState(state);
  if (currentErrors.length) throw new Error(currentErrors.join('; '));
  if (state.stableAction.promotion.state !== 'final') {
    throw new Error('an Action promotion is already pending');
  }
  const next = clone(state);
  next.stableAction.promotion = {
    state: 'pending',
    version: input.version,
    expectedSourceCommit: input.expectedSourceCommit,
    priorTagObject: input.priorTagObject,
  };
  const errors = validateActionPromotionState(next);
  if (errors.length) throw new Error(errors.join('; '));
  return next;
}

export function finalizeActionPromotion(state, sourceCommit) {
  const currentErrors = validateActionPromotionState(state);
  if (currentErrors.length) throw new Error(currentErrors.join('; '));
  const pending = state.stableAction.promotion;
  if (pending.state !== 'pending') throw new Error('no Action promotion is pending');
  if (sourceCommit !== pending.expectedSourceCommit) {
    throw new Error('final source commit differs from the pending promotion');
  }
  const next = clone(state);
  next.stableAction.sourceCommit = sourceCommit;
  next.stableAction.promotion = { state: 'final' };
  const errors = validateActionPromotionState(next);
  if (errors.length) throw new Error(errors.join('; '));
  return next;
}
