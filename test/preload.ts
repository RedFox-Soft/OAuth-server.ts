import { afterEach, beforeEach, setDefaultTimeout } from 'bun:test';

import { jwksStore } from '../lib/adapters/index.js';
import { resetToBaseline } from './addon_baseline.js';
import { installFetchInterception } from './fetch_mock.js';
import { testSigningKeys } from './jwks/fixtures.js';

/*
 * A bound on how long any one case may consume, set here because there is nowhere else to set it.
 * `timeout` is not a bunfig key — Bun's [test] parser handles eighteen and that is not one of them —
 * and the command line is no use either: the merge gate is the bare `bun test`, which resolves to the
 * builtin subcommand, so a `test` script in package.json would be shadowed and a contributor typing
 * the documented command would silently get no bound at all.
 *
 * What it prevents is silence rather than slowness. A case over the limit is interrupted and named;
 * without one, a wedged case prints nothing and idles, which is indistinguishable from a deadlock —
 * a federation case once burned 52 minutes that way and dragged a whole run to 3,226 s. 20 s against
 * a suite that completes 4,036 tests in 66 s leaves every legitimate case two orders of magnitude of
 * headroom. A case that genuinely needs longer passes its own third argument to `it(...)`.
 */
setDefaultTimeout(20_000);

/*
 * No test reaches the real network, in any file order.
 *
 * Before every test rather than once, because Bun restores `globalThis.fetch` at each file boundary —
 * the same fact `fetch_mock.ts` carries its INSTALLED marker for. Here rather than in the specs that
 * happen to stub an outbound call, because the request that escapes is by definition the one nobody
 * thought to stub, and because which files have already run is decided by a walk order that differs
 * between Windows and CI and shifts every time a spec file is added or removed.
 */
beforeEach(installFetchInterception);

// Seed the in-memory jwksStore before any provider import so the store-loading path resolves to
// known keys (replacing the former JWKS env-var seed). Runs as a Bun `preload`, ahead of all specs.
for (const key of testSigningKeys) {
	await jwksStore.set(key.kid, key);
}

let policyControl: { reset(): void } | undefined;
let rateLimiter: { resetRateLimiter(): void } | undefined;

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

	/*
	 * The rate limiter's counters are module state, so nothing else in this suite clears them — and a
	 * spec that runs enough requests through one origin starts seeing 429s in whatever file happens to
	 * cross the allowance first. Reset here rather than in bootstrap() because the specs that trip it
	 * are the ones calling bootstrap in `beforeAll`, where a per-file reset comes too late; and because
	 * the specs that would otherwise have to remember are the ones with no interest in rate limiting.
	 *
	 * Lazily imported for the same reason the policy above is: this file runs ahead of every spec, and
	 * the plugin reaches ApplicationConfig and from there the adapter graph.
	 */
	rateLimiter ??= await import('../lib/plugins/rateLimit.js');
	rateLimiter.resetRateLimiter();
});
