#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

const args = process.argv.slice(2);
let output = 'dist/web-app-security-skill.spdx.json';
let version = readFileSync(new URL('../VERSION', import.meta.url), 'utf8').trim();
while (args.length) {
  const option = args.shift();
  const value = args.shift();
  if (!['--out', '--version'].includes(option) || !value || value.startsWith('--')) {
    console.error('usage: node scripts/generate-sbom.mjs [--out <path>] [--version <semver>]');
    process.exit(2);
  }
  if (option === '--out') output = value;
  if (option === '--version') version = value;
}
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
  console.error('error: --version must be semantic');
  process.exit(2);
}
output = resolve(output);
const digest = createHash('sha256').update(`${version}:parousia8888/web-app-security-skill`).digest('hex');
const created = process.env.SOURCE_DATE_EPOCH
  ? new Date(Number(process.env.SOURCE_DATE_EPOCH) * 1000).toISOString()
  : new Date().toISOString();
const parserManifest = JSON.parse(readFileSync(new URL(
  './vendor/js-ts-parser.manifest.json', import.meta.url), 'utf8'));

const document = {
  spdxVersion: 'SPDX-2.3',
  dataLicense: 'CC0-1.0',
  SPDXID: 'SPDXRef-DOCUMENT',
  name: `web-app-security-skill-${version}`,
  documentNamespace: `https://github.com/parousia8888/web-app-security-skill/sbom/${version}/${digest}`,
  creationInfo: {
    created,
    creators: ['Tool: web-app-security-skill/generate-sbom'],
    licenseListVersion: '3.26',
  },
  packages: [
    {
      name: 'web-app-security-skill',
      SPDXID: 'SPDXRef-Package-web-app-security-skill',
      versionInfo: version,
      downloadLocation: `https://github.com/parousia8888/web-app-security-skill/archive/refs/tags/v${version}.tar.gz`,
      filesAnalyzed: false,
      licenseConcluded: 'MIT',
      licenseDeclared: 'MIT',
      copyrightText: 'NOASSERTION',
      externalRefs: [{
        referenceCategory: 'PACKAGE-MANAGER',
        referenceType: 'purl',
        referenceLocator: `pkg:github/parousia8888/web-app-security-skill@v${version}`,
      }],
    },
    {
      name: parserManifest.component,
      SPDXID: 'SPDXRef-Package-babel-parser',
      versionInfo: parserManifest.version,
      downloadLocation: `https://registry.npmjs.org/@babel/parser/-/parser-${parserManifest.version}.tgz`,
      filesAnalyzed: false,
      licenseConcluded: parserManifest.license,
      licenseDeclared: parserManifest.license,
      copyrightText: 'Copyright (c) 2014-present Sebastian McKenzie and other contributors',
      checksums: [{ algorithm: 'SHA256', checksumValue: parserManifest.sha256 }],
      externalRefs: [{
        referenceCategory: 'PACKAGE-MANAGER',
        referenceType: 'purl',
        referenceLocator: `pkg:npm/%40babel/parser@${parserManifest.version}`,
      }],
      comment: `Bundled runtime output ${parserManifest.output}; npm integrity ${parserManifest.npmIntegrity}`,
    },
  ],
  relationships: [
    {
      spdxElementId: 'SPDXRef-DOCUMENT',
      relationshipType: 'DESCRIBES',
      relatedSpdxElement: 'SPDXRef-Package-web-app-security-skill',
    },
    {
      spdxElementId: 'SPDXRef-Package-web-app-security-skill',
      relationshipType: 'CONTAINS',
      relatedSpdxElement: 'SPDXRef-Package-babel-parser',
    },
  ],
};

mkdirSync(dirname(output), { recursive: true });
writeFileSync(output, `${JSON.stringify(document, null, 2)}\n`);
console.log(output);
