import { afterEach } from 'bun:test';

import { jwksStore } from '../lib/adapters/index.js';
import { resetToBaseline } from './addon_baseline.js';
import { testSigningKeys } from './jwks/fixtures.js';

// Seed the in-memory jwksStore before any provider import so the store-loading path resolves to
// known keys (replacing the former JWKS env-var seed). Runs as a Bun `preload`, ahead of all specs.
for (const key of testSigningKeys) {
	await jwksStore.set(key.kid, key);
}

let policyControl: { reset(): void } | undefined;

// Global isolation hook: after every test, reset the addon override registry to
// the current spec's baseline (the overrides its *.config.ts declared, applied
// by bootstrap). Per-test addons.override(...) calls are wiped so nothing leaks
// between tests; each bootstrap() replaces the baseline so nothing leaks between
// spec files. This is the ONLY reset in the suite.
//
// The interaction policy needs its own reset alongside that one, and the two are not
// interchangeable: resetToBaseline() drops a registered override, while the policy reset
// discards an in-place mutation of a prompt's checks. Only doing one leaks the other.
afterEach(async () => {
	resetToBaseline();
	// Imported lazily: this file is a Bun `preload` that runs ahead of every spec, and the
	// policy module reaches the addon index (via the login prompt) and from there the model
	// graph — which registry.js is deliberately structured to avoid loading this early.
	policyControl ??= (await import('../lib/addon/interactions.js'))
		.interactionPolicyControl;
	policyControl.reset();
});
