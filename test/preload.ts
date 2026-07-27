import { afterEach } from 'bun:test';

import { jwksStore } from '../lib/adapters/index.js';
import { resetToBaseline } from './addon_baseline.js';
import { testSigningKeys } from './jwks/fixtures.js';

// Seed the in-memory jwksStore before any provider import so the store-loading path resolves to
// known keys (replacing the former JWKS env-var seed). Runs as a Bun `preload`, ahead of all specs.
for (const key of testSigningKeys) {
	await jwksStore.set(key.kid, key);
}

// Global isolation hook: after every test, reset the addon override registry to
// the current spec's baseline (the overrides its *.config.ts declared, applied
// by bootstrap). Per-test addons.override(...) calls are wiped so nothing leaks
// between tests; each bootstrap() replaces the baseline so nothing leaks between
// spec files. This is the ONLY reset in the suite.
afterEach(() => {
	resetToBaseline();
});
