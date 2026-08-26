export function validateReleaseTrustLanguage(documents, version) {
  const errors = [];
  const releaseTag = `v${version}`;
  const required = {
    readme: [
      'repository-local signer policy',
      releaseTag,
      'npm OIDC provenance is a separate signal',
    ],
    readmeZh: [
      '仓库内 signer policy',
      releaseTag,
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
  const verificationTags = [
    ...(documents.readme || '').matchAll(/verify-tag (v\d+\.\d+\.\d+)/g),
    ...(documents.readmeZh || '').matchAll(/verify-tag (v\d+\.\d+\.\d+)/g),
  ].map((match) => match[1]);
  if (!verificationTags.length || verificationTags.some((tag) => tag !== releaseTag)) {
    errors.push('README tag verification example is stale');
  }
  if (/signature- and checksum-verified/i.test(documents.readme || '')
      || /签名与 checksum 验证/.test(documents.readmeZh || '')) {
    errors.push('README must not describe optional attestation as verified by default');
  }
  if (!documents.readme?.includes('--attestation required')
      || !documents.readmeZh?.includes('--attestation required')) {
    errors.push('README must expose the fail-closed attestation option');
  }
  return errors;
}
