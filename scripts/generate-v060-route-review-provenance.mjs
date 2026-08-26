#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const REVIEW_JSON = join(ROOT, 'docs', 'reviews', 'v0.6.0-route-review.json');
const REVIEW_MD = join(ROOT, 'docs', 'reviews', 'v0.6.0-route-review.md');
const OUTPUT_JSON = join(ROOT, 'docs', 'reviews', 'v0.6.0-route-review-provenance.json');
const OUTPUT_MD = join(ROOT, 'docs', 'reviews', 'v0.6.0-route-review-provenance.md');
const check = process.argv.includes('--check');
if (process.argv.slice(2).some((item) => item !== '--check')) {
  console.error('usage: node scripts/generate-v060-route-review-provenance.mjs [--check]');
  process.exit(2);
}
const digest = (value) => createHash('sha256').update(value).digest('hex');
const jsonBytes = readFileSync(REVIEW_JSON);
const markdownBytes = readFileSync(REVIEW_MD);
const review = JSON.parse(jsonBytes.toString('utf8'));
const annotationIdentity = digest(JSON.stringify(review.projects.map((project) => ({
  id: project.id,
  commit: project.commit,
  annotations: project.annotations,
}))));
const provenance = {
  schemaVersion: 1,
  evidenceType: 'historical_route_review_provenance',
  release: 'v0.6.0',
  lifecycle: 'historical',
  historicalQualifier: 'The published bytes and manual annotations are preserved. Current analyzer behavior is not claimed to reproduce because the original raw analyzer reports and exact analyzer invocation were not retained.',
  source: {
    publicationCommit: '309fa71c4108a0accbd41c7cae911cca05f9520c',
    releaseCommit: '7521e0699eefe26d23a7972fbee6fb37b46fdfe2',
    toolVersion: '0.6.0',
    targetCommits: Object.fromEntries(review.projects.map((project) => [project.id, project.commit])),
  },
  artifacts: {
    'docs/reviews/v0.6.0-route-review.json': { sha256: digest(jsonBytes) },
    'docs/reviews/v0.6.0-route-review.md': { sha256: digest(markdownBytes) },
    manualAnnotationIdentity: { sha256: annotationIdentity },
  },
  reproducibility: {
    byteGenerationCommand: 'SOURCE_DATE_EPOCH=0 node scripts/generate-v060-route-review.mjs --check',
    byteIdentity: 'reproducible',
    manualAnnotationIdentity: 'reproducible',
    currentAnalyzerBehavior: 'verification_pending',
    missingEvidence: [
      'Original per-project route-security.json artifacts',
      'Exact analyzer invocation and environment for each project',
      'Sanitized raw comparison log connecting analyzer records to the 57 manual annotations',
    ],
  },
  refreshContract: {
    policy: 'Do not overwrite v0.6.0 artifacts. Publish a new versioned review with exact tool commit, target commits, commands, exits, byte digests, semantic digests and raw sanitized artifacts.',
    command: 'node scripts/generate-v070-access-review.mjs --check',
  },
};
const markdown = `# v0.6.0 route-review provenance\n\n`
  + `This sidecar classifies the existing v0.6.0 route review as **historical evidence**. It does not alter the original JSON, Markdown, findings or annotations.\n\n`
  + `- Publication commit: \`${provenance.source.publicationCommit}\`\n`
  + `- Signed-release source commit: \`${provenance.source.releaseCommit}\`\n`
  + `- Tool version recorded by the release: \`${provenance.source.toolVersion}\`\n`
  + `- JSON SHA-256: \`${provenance.artifacts['docs/reviews/v0.6.0-route-review.json'].sha256}\`\n`
  + `- Markdown SHA-256: \`${provenance.artifacts['docs/reviews/v0.6.0-route-review.md'].sha256}\`\n`
  + `- Manual-annotation identity: \`${provenance.artifacts.manualAnnotationIdentity.sha256}\`\n\n`
  + `## Reproducibility classification\n\n`
  + `- Published bytes: \`reproducible\` with \`${provenance.reproducibility.byteGenerationCommand}\`.\n`
  + `- Manual annotation identity: \`reproducible\`.\n`
  + `- Current analyzer behavior: \`verification_pending\`. The original raw route reports and exact per-project analyzer commands were not retained, so current behavior cannot be inferred from identical generated prose.\n\n`
  + `## Target commits\n\n`
  + Object.entries(provenance.source.targetCommits).map(([id, commit]) => `- ${id}: \`${commit}\``).join('\n')
  + `\n\n## Refresh contract\n\n${provenance.refreshContract.policy}\n`;
const outputs = [
  [OUTPUT_JSON, `${JSON.stringify(provenance, null, 2)}\n`],
  [OUTPUT_MD, markdown],
];
for (const [path, content] of outputs) {
  if (check) {
    if (readFileSync(path, 'utf8') !== content) {
      console.error(`${path} is stale`);
      process.exit(1);
    }
  } else writeFileSync(path, content);
}
console.log(`v0.6.0 route provenance ${check ? 'current' : 'generated'}: bytes reproducible, analyzer behavior verification_pending`);
