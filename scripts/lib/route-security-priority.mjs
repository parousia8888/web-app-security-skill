const UNRESOLVED = new Set(['candidate_observed', 'not_observed', 'incomplete']);

export function prioritizeRoute(route) {
  const reasons = [];
  const authnUnresolved = UNRESOLVED.has(route.authentication.state);
  const authzUnresolved = UNRESOLVED.has(route.authorization.state);
  if (route.operations.length && authzUnresolved) reasons.push('sensitive-operation-authorization-unresolved');
  if (route.objectAddressed && authzUnresolved) reasons.push('object-authorization-unresolved');
  if (route.stateChanging && authnUnresolved) reasons.push('state-change-authentication-unresolved');
  if (route.stateChanging && authzUnresolved) reasons.push('state-change-authorization-unresolved');
  let level = 'no_automatic_priority';
  if (reasons.includes('sensitive-operation-authorization-unresolved')) level = 'review_first';
  else if (route.stateChanging || route.objectAddressed) level = reasons.length ? 'review_next' : 'no_automatic_priority';
  else if (authnUnresolved || authzUnresolved) level = 'review_later';
  return { ...route, priority: { level, reasons } };
}
