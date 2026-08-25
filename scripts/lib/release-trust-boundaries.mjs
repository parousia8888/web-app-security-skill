export function validateReleaseTrustLanguage(documents) {
  const errors = [];
  const required = {
    readme: [
      'repository-local signer policy',
      'v0.7.2',
      'npm OIDC provenance is a separate signal',
    ],
    readmeZh: [
      '仓库内 signer policy',
      'v0.7.2',
      'npm OIDC provenance 是另一条独立信号',
    ],
    security: ['release-trust-boundaries.md', 'repository-consistency check'],
    trust: [
      'release tag source commit = release manifest source commit = npm gitHead = immutable Action commit',
      'does not independently prove GitHub account ownership',
      '`main` HEAD is not required to equal the release source commit',
      'It covers the npm package.',
    ],
  };
  for (const [name, markers] of Object.entries(required)) {
    for (const marker of markers) {
      if (!documents[name]?.includes(marker)) errors.push(`${name} is missing ${marker}`);
    }
  }
  if (/verify-tag v0\.6\.0/.test(documents.readme || '')
      || /verify-tag v0\.6\.0/.test(documents.readmeZh || '')) {
    errors.push('README tag verification example is stale');
  }
  return errors;
}
