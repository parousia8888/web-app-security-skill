const CONTROL_PRIMITIVES = new Map([
  ['passport:authenticate', { kind: 'passport-authenticate', role: 'authentication' }],
  ['express-jwt:expressjwt', { kind: 'express-jwt', role: 'authentication' }],
  ['express-oauth2-jwt-bearer:auth', { kind: 'oauth2-jwt-auth', role: 'authentication' }],
  ['@auth0/express-openid-connect:requiresAuth', { kind: 'auth0-requires-auth', role: 'authentication' }],
  ['@clerk/express:requireAuth', { kind: 'clerk-require-auth', role: 'authentication' }],
  ['express-jwt-permissions:check', { kind: 'express-jwt-permission-check', role: 'authorization' }],
  ['@nestjs/passport:AuthGuard', { kind: 'nest-passport-auth-guard', role: 'authentication' }],
  ['nest-keycloak-connect:AuthGuard', { kind: 'nest-keycloak-auth-guard', role: 'authentication' }],
  ['nest-keycloak-connect:ResourceGuard', { kind: 'nest-keycloak-resource-guard', role: 'authorization' }],
  ['nest-keycloak-connect:RoleGuard', { kind: 'nest-keycloak-role-guard', role: 'authorization' }],
  ['next-auth:getServerSession', { kind: 'next-auth-session', role: 'authentication' }],
  ['next-auth/next:getServerSession', { kind: 'next-auth-session', role: 'authentication' }],
  ['@clerk/nextjs/server:auth', { kind: 'clerk-auth', role: 'authentication' }],
  ['@clerk/nextjs/server:currentUser', { kind: 'clerk-current-user', role: 'authentication' }],
  ['@auth0/nextjs-auth0:getSession', { kind: 'auth0-session', role: 'authentication' }],
]);

export function exactControlPrimitive(source, imported) {
  return CONTROL_PRIMITIVES.get(`${source}:${imported}`) || null;
}

export function signalForPrimitive(source, imported, location) {
  const primitive = exactControlPrimitive(source, imported);
  if (!primitive) return null;
  return { ...primitive, origin: `${source}:${imported}`, location, exact: true };
}

export function signalsForRole(signals, role) {
  return signals.filter((signal) => signal.role === role);
}

export function unclassifiedSignals(signals) {
  return signals.filter((signal) => signal.role === 'unknown');
}

export function exactSignalsForRole(signals, role) {
  return signals.filter((signal) => signal.exact && signal.role === role);
}

export function controlPrimitiveInventory() {
  return [...CONTROL_PRIMITIVES.entries()].map(([identity, value]) => ({ identity, ...value }));
}
