import { defineConfig } from 'tsup'

/**
 * Library build. `libsodium-wrappers` and `hash-wasm` are kept external
 * (declared as runtime dependencies) so the consuming app bundles them —
 * both ship their WASM embedded as base64 in-JS, so nothing is fetched as
 * remote code (a hard requirement for the MV3 browser extension).
 */
export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  target: 'es2022',
})
