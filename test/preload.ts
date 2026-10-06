import { afterEach, beforeEach } from 'bun:test';

import { writeRootKeys } from './root_keys.js';
import { resetToBaseline } from './addon_baseline.js';
import { installFetchInterception } from './fetch_mock.js';
import { resolver } from '../lib/shared/egress.js';
import { testSigningKeys } from './jwks/fixtures.js';

/*
 * No time limit is set here, though one was for a long while: `setDefaultTimeout` applies to "all tests
 * in the current file" (Bun's reference), so called from a preload it bounded only the first spec of a
 * run at 20 s, and every other spec has always run under Bun's own default of 5 s. Neither a bunfig
 * `timeout` key nor a preload hook carries a default across files; only `bun test --timeout` does, and
 * the gate is the bare command. 5 s is therefore the bound every case actually has. A case that needs
 * longer passes its own third argument to `it(...)`.
 */

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

/*
 * Name resolution is network too. Every outbound request to an address a client supplied checks what
 * that name resolves to (lib/shared/egress.ts), and a spec naming `https://rp.example.com` means a
 * public host, not whatever the machine running it can resolve today — an offline run would otherwise
 * refuse it as unresolvable, and an online one would send the query. Each test starts with every name
 * resolving to one public address; a spec about the address rules sets its own answer.
 */
beforeEach(() => {
	resolver.lookup = async () => ['93.184.216.34'];
});

// Seed the root keys before any provider import so the first load resolves to known keys. Runs as a Bun
// `preload`, ahead of all specs.
await writeRootKeys(testSigningKeys);

// The settings baseline every bootstrap restores, taken now — after the keys above, before any spec.
await import('./config_baseline.js');

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
