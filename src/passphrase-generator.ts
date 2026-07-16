import { wordlist as englishWordlist } from '@scure/bip39/wordlists/english.js'

/** Cryptographically strong Diceware-style passphrases. */
export const PASSPHRASE_MIN_WORDS = 4
export const PASSPHRASE_MAX_WORDS = 10
export const PASSPHRASE_DEFAULT_WORDS = 6

export const PASSPHRASE_SEPARATORS = ['-', '.', '_', ' '] as const
export type PassphraseSeparator = (typeof PASSPHRASE_SEPARATORS)[number]

export interface PassphraseOptions {
  words: number
  separator: PassphraseSeparator
  capitalize: boolean
  includeNumber: boolean
}

function randomIndex(max: number): number {
  if (!Number.isSafeInteger(max) || max < 1 || max > 65_536) {
    throw new RangeError('Random range must be an integer between 1 and 65536')
  }

  const limit = 65_536 - (65_536 % max)
  const buffer = new Uint16Array(1)
  for (;;) {
    crypto.getRandomValues(buffer)
    if (buffer[0] < limit) return buffer[0] % max
  }
}

function capitalize(word: string): string {
  return `${word.slice(0, 1).toUpperCase()}${word.slice(1)}`
}

/**
 * Generate a passphrase from the audited 2048-word BIP39 English list.
 * Six words provide 66 bits of word-selection entropy before optional digits.
 */
export function generatePassphrase(options: PassphraseOptions): string {
  const wordCount = Math.min(
    PASSPHRASE_MAX_WORDS,
    Math.max(PASSPHRASE_MIN_WORDS, Math.floor(options.words)),
  )
  if (!PASSPHRASE_SEPARATORS.includes(options.separator)) {
    throw new RangeError('Unsupported passphrase separator')
  }

  const words = Array.from({ length: wordCount }, () => {
    const word = englishWordlist[randomIndex(englishWordlist.length)]
    return options.capitalize ? capitalize(word) : word
  })

  if (options.includeNumber) {
    const index = randomIndex(words.length)
    words[index] = `${words[index]}${randomIndex(10)}`
  }

  return words.join(options.separator)
}
