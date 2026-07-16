import { describe, expect, it } from 'vitest'
import {
  PASSWORD_DEFAULT_LENGTH,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  generatePassword,
  type PasswordOptions,
} from './password-generator'

const LOWER = /[a-z]/
const UPPER = /[A-Z]/
const DIGIT = /[0-9]/
const SYMBOL = /[!@#$%^&*()\-_=+[\]{};:,.?/]/

function gen(overrides: Partial<PasswordOptions> = {}): string {
  return generatePassword({ length: PASSWORD_DEFAULT_LENGTH, digits: true, symbols: true, ...overrides })
}

describe('generatePassword', () => {
  it('honours the requested length', () => {
    for (const length of [PASSWORD_MIN_LENGTH, 20, 33, PASSWORD_MAX_LENGTH]) {
      expect(gen({ length })).toHaveLength(length)
    }
  })

  it('clamps length to the supported range', () => {
    expect(gen({ length: 1 })).toHaveLength(PASSWORD_MIN_LENGTH)
    expect(gen({ length: 999 })).toHaveLength(PASSWORD_MAX_LENGTH)
  })

  it('always includes lowercase and uppercase', () => {
    for (let i = 0; i < 50; i++) {
      const pw = gen({ digits: false, symbols: false })
      expect(pw).toMatch(LOWER)
      expect(pw).toMatch(UPPER)
      expect(pw).not.toMatch(DIGIT)
      expect(pw).not.toMatch(SYMBOL)
    }
  })

  it('includes at least one digit when enabled, none when disabled', () => {
    for (let i = 0; i < 50; i++) {
      expect(gen({ digits: true, symbols: false })).toMatch(DIGIT)
      expect(gen({ digits: false, symbols: false })).not.toMatch(DIGIT)
    }
  })

  it('includes at least one symbol when enabled, none when disabled', () => {
    for (let i = 0; i < 50; i++) {
      expect(gen({ digits: false, symbols: true })).toMatch(SYMBOL)
      expect(gen({ digits: false, symbols: false })).not.toMatch(SYMBOL)
    }
  })

  it('guarantees one of every enabled class even at the minimum length', () => {
    for (let i = 0; i < 50; i++) {
      const pw = gen({ length: PASSWORD_MIN_LENGTH, digits: true, symbols: true })
      expect(pw).toMatch(LOWER)
      expect(pw).toMatch(UPPER)
      expect(pw).toMatch(DIGIT)
      expect(pw).toMatch(SYMBOL)
    }
  })

  it('does not pin guaranteed characters to a fixed position (is shuffled)', () => {
    // Across many draws the first character should vary across classes, not
    // always be the lowercase seed.
    const firsts = new Set<string>()
    for (let i = 0; i < 100; i++) firsts.add(gen()[0])
    expect(firsts.size).toBeGreaterThan(5)
  })

  it('produces distinct values on repeated calls', () => {
    const values = new Set(Array.from({ length: 20 }, () => gen()))
    expect(values.size).toBe(20)
  })
})
