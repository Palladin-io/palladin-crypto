import { execFileSync } from 'node:child_process'
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, it } from 'vitest'

it('records both installed versions and resolves each dependency from its parent', () => {
  const root = mkdtempSync(join(tmpdir(), 'palladin-oss-'))
  try {
    mkdirSync(join(root, 'scripts'))
    copyFileSync(new URL('./generate-oss-metadata.mjs', import.meta.url), join(root, 'scripts/generate-oss-metadata.mjs'))
    writeFileSync(join(root, 'package.json'), JSON.stringify({ name: '@palladin/crypto', version: '1.0.0', dependencies: { hash: '2.0.0', words: '1.0.0' } }))
    const packages = {
      'node_modules/hash': { version: '2.0.0', license: 'MIT' },
      'node_modules/words': { version: '1.0.0', license: 'MIT', dependencies: { hash: '1.0.0', helper: '1.0.0' } },
      'node_modules/words/node_modules/hash': { version: '1.0.0', license: 'MIT' },
      'node_modules/helper': { version: '1.0.0', license: 'MIT', dependencies: { hash: '2.0.0' } },
    }
    writeFileSync(join(root, 'package-lock.json'), JSON.stringify({ packages }))
    for (const [path, entry] of Object.entries(packages)) {
      mkdirSync(join(root, path), { recursive: true })
      writeFileSync(join(root, path, 'LICENSE'), `Synthetic license ${path} ${entry.version}`)
    }
    const generate = (...args: string[]) => execFileSync(process.execPath, [join(root, 'scripts/generate-oss-metadata.mjs'), ...args], { stdio: 'pipe' })
    generate()
    const bom = JSON.parse(readFileSync(join(root, 'SBOM.cdx.json'), 'utf8'))
    expect(bom.components.map((value: { purl: string }) => value.purl).sort()).toEqual([
      'pkg:npm/hash@1.0.0', 'pkg:npm/hash@2.0.0', 'pkg:npm/helper@1.0.0', 'pkg:npm/words@1.0.0',
    ])
    expect(bom.dependencies).toContainEqual({ ref: 'pkg:npm/words@1.0.0', dependsOn: ['pkg:npm/hash@1.0.0', 'pkg:npm/helper@1.0.0'] })
    expect(bom.dependencies).toContainEqual({ ref: 'pkg:npm/helper@1.0.0', dependsOn: ['pkg:npm/hash@2.0.0'] })
    const notices = readFileSync(join(root, 'THIRD_PARTY_NOTICES.md'), 'utf8')
    expect(notices).toContain('Synthetic license node_modules/hash 2.0.0')
    expect(notices).toContain('Synthetic license node_modules/words/node_modules/hash 1.0.0')
    expect(() => generate('--check')).not.toThrow()
    writeFileSync(join(root, 'SBOM.cdx.json'), '{}')
    expect(() => generate('--check')).toThrow()
  } finally { rmSync(root, { recursive: true, force: true }) }
})
