import { wordlist as englishWordlist } from '@scure/bip39/wordlists/english.js'
import { describe, expect, it } from 'vitest'
import {
  PASSPHRASE_DEFAULT_WORDS,
  PASSPHRASE_MAX_WORDS,
  PASSPHRASE_MIN_WORDS,
  generatePassphrase,
  type PassphraseOptions,
} from './passphrase-generator'

function generate(overrides: Partial<PassphraseOptions> = {}): string {
  return generatePassphrase({
    words: PASSPHRASE_DEFAULT_WORDS,
    separator: '-',
    capitalize: false,
    includeNumber: false,
    ...overrides,
  })
}

describe('generatePassphrase', () => {
  it('uses the requested number of words from the bundled wordlist', () => {
    const words = generate().split('-')
    expect(words).toHaveLength(PASSPHRASE_DEFAULT_WORDS)
    expect(words.every((word) => englishWordlist.includes(word))).toBe(true)
  })

  it('clamps the word count to the supported range', () => {
    expect(generate({ words: 1 }).split('-')).toHaveLength(PASSPHRASE_MIN_WORDS)
    expect(generate({ words: 999 }).split('-')).toHaveLength(PASSPHRASE_MAX_WORDS)
  })

  it('supports separators and capitalization', () => {
    const words = generate({ separator: '.', capitalize: true }).split('.')
    expect(words).toHaveLength(PASSPHRASE_DEFAULT_WORDS)
    expect(words.every((word) => /^[A-Z][a-z]+$/.test(word))).toBe(true)
  })

  it('adds exactly one digit when requested', () => {
    const phrase = generate({ includeNumber: true })
    expect(phrase.match(/\d/g)).toHaveLength(1)
  })

  it('rejects separators outside the public allowlist', () => {
    expect(() => generate({ separator: '/' as PassphraseOptions['separator'] })).toThrow(RangeError)
  })

  it('produces distinct values on repeated calls', () => {
    const values = new Set(Array.from({ length: 20 }, () => generate()))
    expect(values.size).toBe(20)
  })
})
