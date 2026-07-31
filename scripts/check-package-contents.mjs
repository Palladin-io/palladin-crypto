#!/usr/bin/env node
import { execFileSync } from 'node:child_process';

const npmCli = process.env.npm_execpath;
if (!npmCli) throw new Error('npm_execpath is unavailable');
const output = execFileSync(process.execPath, [npmCli, 'pack', '--dry-run', '--json'], {
  encoding: 'utf8',
  env: { ...process.env, npm_config_loglevel: 'silent' },
  maxBuffer: 16 * 1024 * 1024,
});
const jsonStart = output.lastIndexOf('\n[\n');
const packs = JSON.parse(output.slice(jsonStart < 0 ? 0 : jsonStart + 1));
const paths = packs[0]?.files?.map((file) => file.path).sort();
if (!Array.isArray(paths)) throw new Error('npm pack did not return a package file list');

const required = [
  'LICENSE', 'NOTICE', 'README.md', 'SBOM.cdx.json',
  'THIRD_PARTY_NOTICES.md', 'TRADEMARKS.md', 'package.json',
];
for (const path of required) {
  if (!paths.includes(path)) throw new Error(`published package is missing ${path}`);
}
for (const path of paths) {
  if (!required.includes(path) && !path.startsWith('dist/')) {
    throw new Error(`unexpected file in published package: ${path}`);
  }
}
