const PRINCIPAL_KEY = /^(?:owner|user|account|member)(?:_?id)?$/i;
const TENANT_KEY = /^(?:tenant|organization|org)(?:_?id)?$/i;
const OBJECT_KEY = /^(?:id|.*Id|.*_id)$/;

function terminalName(value) {
  return String(value || '').split('.').at(-1);
}

export function accessControlKeyCategory(value) {
  const name = terminalName(value);
  if (TENANT_KEY.test(name)) return 'tenant';
  if (PRINCIPAL_KEY.test(name)) return 'principal';
  if (OBJECT_KEY.test(name)) return 'object';
  return null;
}

export function isPrincipalOrTenantKey(value) {
  return ['principal', 'tenant'].includes(accessControlKeyCategory(value));
}

export function isPrincipalExpressionName(value, aliases = new Set()) {
  const name = String(value || '');
  if (!name) return false;
  if (aliases.has(name)) return true;
  if (isPrincipalOrTenantKey(name)) return true;
  return /^(?:req|request|ctx|context|session|auth|principal|user)(?:\.[A-Za-z_$][\w$]*)*\.(?:id|userId|user_id|ownerId|owner_id|tenantId|tenant_id|organizationId|organization_id|orgId|org_id|accountId|account_id|memberId|member_id)$/i.test(name);
}

export function accessControlVocabularyInventory() {
  return {
    principal: ['ownerId', 'owner_id', 'userId', 'user_id', 'accountId', 'account_id', 'memberId', 'member_id'],
    tenant: ['tenantId', 'tenant_id', 'organizationId', 'organization_id', 'orgId', 'org_id'],
  };
}
