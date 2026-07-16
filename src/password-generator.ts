/**
 * Cryptographically-strong password generator for entry secrets.
 *
 * Uses `crypto.getRandomValues` with rejection sampling so every character is
 * drawn uniformly from the alphabet — no modulo bias. Lowercase and uppercase
 * are always included; digits and symbols are opt-in. The result is guaranteed
 * to contain at least one character from every enabled class (so it satisfies
 * common "must include a number/symbol" policies) while staying uniformly
 * random beyond that guarantee.
 *
 * The generated value is a secret: it must never be logged, sent to analytics,
 * or persisted anywhere outside the in-memory field the user pastes it into.
 */

export const PASSWORD_MIN_LENGTH = 8
export const PASSWORD_MAX_LENGTH = 64
export const PASSWORD_DEFAULT_LENGTH = 20

const LOWER = 'abcdefghijklmnopqrstuvwxyz'
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
const DIGITS = '0123456789'
// Deliberately avoids ambiguous/space-like and quote characters that break
// shell/CSV round-trips; still a broad symbol set for entropy.
const SYMBOLS = '!@#$%^&*()-_=+[]{};:,.?/'

export interface PasswordOptions {
  length: number
  digits: boolean
  symbols: boolean
}

/** Character classes that are always or conditionally part of the alphabet. */
function classesFor(options: PasswordOptions): string[] {
  const classes = [LOWER, UPPER]
  if (options.digits) classes.push(DIGITS)
  if (options.symbols) classes.push(SYMBOLS)
  return classes
}

/**
 * Uniform random integer in `[0, max)` via rejection sampling on a byte. `max`
 * is always ≤ our largest alphabet (well under 256), so a single byte suffices.
 */
function randomIndex(max: number): number {
  // Largest multiple of `max` that fits in a byte; bytes at or above it are
  // rejected so the remainder never skews the distribution.
  const limit = 256 - (256 % max)
  const buf = new Uint8Array(1)
  for (;;) {
    crypto.getRandomValues(buf)
    if (buf[0] < limit) return buf[0] % max
  }
}

function pick(alphabet: string): string {
  return alphabet[randomIndex(alphabet.length)]
}

/** Fisher–Yates shuffle using the same unbiased sampler. */
function shuffle(chars: string[]): string[] {
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomIndex(i + 1)
    ;[chars[i], chars[j]] = [chars[j], chars[i]]
  }
  return chars
}

/**
 * Generate a password satisfying `options`. Length is clamped to
 * `[PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH]`.
 */
export function generatePassword(options: PasswordOptions): string {
  const length = Math.min(
    PASSWORD_MAX_LENGTH,
    Math.max(PASSWORD_MIN_LENGTH, Math.floor(options.length)),
  )
  const classes = classesFor(options)
  const all = classes.join('')

  // One guaranteed character per enabled class, then fill the rest uniformly
  // from the full alphabet; shuffle so the guaranteed characters aren't pinned
  // to the front.
  const chars: string[] = classes.map(pick)
  while (chars.length < length) chars.push(pick(all))
  return shuffle(chars).join('')
}
