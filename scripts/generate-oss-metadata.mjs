#!/usr/bin/env node
import { lstatSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const check = args.length === 1 && args[0] === '--check';
if (args.length > 0 && !check) throw new Error('usage: generate-oss-metadata.mjs [--check]');

const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));

function packagePath(name) {
  return `node_modules/${name}`;
}

const selected = new Map();
const pending = Object.keys(manifest.dependencies);
while (pending.length > 0) {
  const name = pending.shift();
  if (selected.has(name)) continue;
  const entry = lock.packages[packagePath(name)];
  if (!entry || entry.dev === true) throw new Error(`missing locked production dependency: ${name}`);
  selected.set(name, entry);
  pending.push(...Object.keys(entry.dependencies ?? {}));
}
const dependencies = [...selected].sort(([left], [right]) => left.localeCompare(right));

function licenseDocuments(name) {
  const directory = join(root, packagePath(name));
  const documents = readdirSync(directory)
    .filter((file) => /^(?:licen[cs]e|copying|notice)(?:\.|$)/i.test(file))
    .sort()
    .map((file) => {
      const path = join(directory, file);
      const stat = lstatSync(path);
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`unsafe license document: ${path}`);
      return { file, text: readFileSync(path, 'utf8').replace(/\r\n/g, '\n').trimEnd() };
    });
  if (documents.length === 0) throw new Error(`no license document found for ${name}`);
  return documents;
}

const notice = [
  '# Third-Party Notices',
  '',
  'The published `@palladin/crypto` package includes the production dependencies',
  'listed below. Versions come from `package-lock.json`; license texts are copied',
  'verbatim from the corresponding installed package.',
  '',
];
for (const [name, entry] of dependencies) {
  notice.push(`## ${name} ${entry.version} — ${entry.license}`, '');
  notice.push(`Upstream package: https://www.npmjs.com/package/${name}/v/${entry.version}`, '');
  for (const document of licenseDocuments(name)) {
    notice.push(`### ${document.file}`, '', document.text, '');
  }
}

function npmPurl(name, version) {
  const encoded = name.startsWith('@')
    ? `%40${name.slice(1).split('/').map(encodeURIComponent).join('/')}`
    : encodeURIComponent(name);
  return `pkg:npm/${encoded}@${version}`;
}

function component(name, entry) {
  const purl = npmPurl(name, entry.version);
  const value = {
    'bom-ref': purl,
    type: 'library',
    name,
    version: entry.version,
    purl,
    scope: 'required',
    licenses: /^[A-Za-z0-9-.+]+$/.test(entry.license)
      ? [{ license: { id: entry.license } }]
      : [{ expression: entry.license }],
  };
  if (entry.integrity) {
    const [algorithm, encoded] = entry.integrity.split('-', 2);
    if (algorithm && encoded) {
      value.hashes = [{ alg: algorithm.toUpperCase().replace('SHA', 'SHA-'), content: Buffer.from(encoded, 'base64').toString('hex') }];
    }
  }
  if (entry.resolved) value.externalReferences = [{ type: 'distribution', url: entry.resolved }];
  return value;
}

const rootRef = npmPurl(manifest.name, manifest.version);
const sbom = {
  '$schema': 'https://cyclonedx.org/schema/bom-1.6.schema.json',
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  version: 1,
  metadata: {
    lifecycles: [{ phase: 'pre-build' }],
    component: {
      'bom-ref': rootRef,
      type: 'library',
      group: '@palladin',
      name: 'crypto',
      version: manifest.version,
      description: manifest.description,
      purl: rootRef,
      licenses: [{ license: { id: 'Apache-2.0' } }],
    },
  },
  components: dependencies.map(([name, entry]) => component(name, entry)),
  dependencies: [
    { ref: rootRef, dependsOn: Object.keys(manifest.dependencies).sort().map((name) => npmPurl(name, selected.get(name).version)) },
    ...dependencies.map(([name, entry]) => ({
      ref: npmPurl(name, entry.version),
      dependsOn: Object.keys(entry.dependencies ?? {}).sort().map((child) => npmPurl(child, selected.get(child).version)),
    })),
  ],
};

const outputs = new Map([
  [join(root, 'THIRD_PARTY_NOTICES.md'), notice.join('\n')],
  [join(root, 'SBOM.cdx.json'), `${JSON.stringify(sbom, null, 2)}\n`],
]);
for (const [path, expected] of outputs) {
  if (check) {
    if (readFileSync(path, 'utf8') !== expected) {
      throw new Error(`${path} is stale; run npm run oss:generate`);
    }
  } else {
    writeFileSync(path, expected, { mode: 0o644 });
  }
}
