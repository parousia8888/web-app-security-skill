#!/usr/bin/env node
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (path) => readFileSync(`${ROOT}/${path}`, 'utf8');
const ci = read('.github/workflows/ci.yml');
const installer = read('test/install-pinned-shellcheck.sh');
const alertPolicy = read('docs/alert-policy.md');
const dispositions = read('docs/code-scanning-dispositions.md');
const quickstartBefore = JSON.parse(read('examples/quickstart/before/package.json'));
const quickstartAfter = JSON.parse(read('examples/quickstart/after/package.json'));
const quickstartAfterLock = JSON.parse(read('examples/quickstart/after/package-lock.json'));
const platformEvidence = JSON.parse(read('docs/releases/v0.8.1-platform-governance.json'));

assert.match(ci,
  /actions\/dependency-review-action@3c4e3dcb1aa7874d2c16be7d79418e9b7efd6261/);
assert.match(ci, /dependency-review:[\s\S]*github\.event_name == 'pull_request'/);
assert.match(ci, /fail-on-severity:\s*["']moderate["']/,
  'moderate and higher dependency changes are blocking');
assert.match(ci, /shellcheck:[\s\S]*bash test\/install-pinned-shellcheck\.sh/);
assert.match(ci, /shellcheck --severity=warning --external-sources scripts\/\*\.sh test\/\*\.sh/);
assert.match(installer, /version=["']0\.11\.0["']/);
assert.match(installer, /8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198/);
assert.match(installer, /56affdd8de5527894dca6dc3d7e0a99a873b0f004d7aabc30ae407d3f48b0a79/);
assert.match(installer, /sha256sum --check --strict/);
assert.match(installer, /--proto '=https'/);
assert.doesNotMatch(ci, /coverage-threshold|--coverage/,
  'v0.8.1 does not invent a code-coverage percentage gate');
for (const marker of [
  '@parousia8888', 'HIGH secret: one business day',
  'dependency finding: three business days', 'The private reporting process in `SECURITY.md`',
]) assert.ok(alertPolicy.includes(marker), `alert owner policy is missing ${marker}`);
for (const alert of [1, 2, 3, 4, 5, 6, 7, 9, 10, 11]) {
  assert.match(dispositions, new RegExp(`\\| ${alert} \\|`));
}
assert.equal(quickstartBefore.dependencies.next, quickstartAfter.dependencies.next,
  'quickstart variants must not differ by an unrelated vulnerable framework version');
assert.equal(existsSync(`${ROOT}/examples/quickstart/before/package-lock.json`), false,
  'the before fixture intentionally demonstrates missing lockfile evidence');
assert.equal(quickstartAfterLock.packages[''].dependencies.next, quickstartAfter.dependencies.next,
  'the hardened fixture lockfile must govern its declared Next version');
assert.equal(quickstartAfterLock.packages['node_modules/next'].version,
  quickstartAfter.dependencies.next, 'the hardened fixture must lock the declared Next version');
assert.equal(platformEvidence.repositoryProtection.main.forcePushAllowed, false);
assert.equal(platformEvidence.repositoryProtection.main.deletionAllowed, false);
assert.deepEqual(platformEvidence.repositoryProtection.tagRulesets.map((item) => item.include[0]),
  ['refs/tags/v0.*', 'refs/tags/v1']);
assert.equal(platformEvidence.repositoryProtection.releaseEnvironment.protectedBranchesOnly, true);
assert.equal(platformEvidence.securityAnalysis.dependabotVulnerabilityAlerts, 'enabled');
assert.equal(platformEvidence.securityAnalysis.dependabotSecurityUpdates, 'enabled');
assert.deepEqual(platformEvidence.dependabotInventory.manifestPaths,
  ['examples/quickstart/before/package.json']);
assert.equal(platformEvidence.dependabotInventory.disposition, 'pending_candidate_fix');
assert.deepEqual(platformEvidence.codeScanningInventory.productionAlertsAwaitingCandidateAnalysis,
  [9, 10]);
assert.deepEqual(platformEvidence.codeScanningInventory.testOrFixtureAlertsAwaitingPublicLedger,
  [1, 2, 3, 4, 5, 6, 7, 11]);

console.log('v0.8.1 platform governance contract ok: dependency review, pinned ShellCheck and owner policy');
