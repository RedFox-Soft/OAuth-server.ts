import { describe, it, beforeEach, afterEach, expect, mock } from 'bun:test';

import bootstrap from '../test_helper.js';
import { validateConfiguration } from 'lib/configs/configuration.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { SETTINGS_CATALOG } from 'lib/admin/settings/catalog.js';
import { eventBus } from 'lib/event_bus.js';
import { ORIGIN_A, flood, refusals, resetRateLimiter } from './helper.js';

/*
 * The startup gate (FR-009).
 *
 * Both ways of getting these numbers wrong fail silently at runtime, which is why they have to fail
 * loudly at boot: a non-positive allowance refuses every request, and a non-positive window makes
 * every request look like the first of a new one. Neither throws, neither logs, and both look like a
 * working server until someone reads the traffic.
 *
 * validateConfiguration is the right place because the admin settings PUT delegates to it — so boot
 * and the API cannot disagree about what is valid.
 */
const NUMERIC_KEYS = [
	'rateLimit.strict.max',
	'rateLimit.strict.windowSeconds',
	'rateLimit.ordinary.max',
	'rateLimit.ordinary.windowSeconds',
	'rateLimit.public.max',
	'rateLimit.public.windowSeconds',
	'rateLimit.maxTrackedOrigins'
] as const;

const REJECTED = [
	['zero', 0],
	['a negative', -1],
	['a fraction', 1.5],
	['not a number', 'sixty'],
	['NaN', Number.NaN],
	['Infinity', Number.POSITIVE_INFINITY]
] as const;

function withKey(key: string, value: unknown) {
	return { ...ApplicationConfig, [key]: value };
}

describe('rate limit configuration', () => {
	it('accepts the shipped defaults', () => {
		expect(() => validateConfiguration({ ...ApplicationConfig })).not.toThrow();
	});

	for (const key of NUMERIC_KEYS) {
		describe(key, () => {
			for (const [label, value] of REJECTED) {
				it(`refuses ${label}, naming the key`, () => {
					expect(() => validateConfiguration(withKey(key, value))).toThrow(
						TypeError
					);
					// The message has to name the offending setting: an operator reading a failed boot has
					// nine of these to choose from.
					expect(() => validateConfiguration(withKey(key, value))).toThrow(key);
				});
			}

			it('accepts one, the smallest workable value', () => {
				expect(() => validateConfiguration(withKey(key, 1))).not.toThrow();
			});
		});
	}

	// The switches are booleans and carry no arithmetic, so they have no invariant of their own —
	// pinned so that a later change making them numeric does not slip past this suite.
	it('leaves the two switches unvalidated beyond their type', () => {
		expect(() =>
			validateConfiguration(withKey('rateLimit.enabled', false))
		).not.toThrow();
		expect(() =>
			validateConfiguration(withKey('rateLimit.trustedProxy', false))
		).not.toThrow();
	});

	/*
	 * A disabled limiter still has to hold a valid configuration. The alternative — skipping the checks
	 * when the switch is off — means an operator turns the limiter on months later and the server
	 * refuses to boot, with the offending value having been accepted at the time it was written.
	 */
	it('validates the numbers even when the limiter is switched off', () => {
		const off = {
			...ApplicationConfig,
			'rateLimit.enabled': false,
			'rateLimit.strict.max': 0
		};

		expect(() => validateConfiguration(off)).toThrow(TypeError);
	});

	/*
	 * FR-020. SETTINGS_CATALOG "drives the API whitelist, server-side validation, and the UI form", so a
	 * key missing from it is unreachable through the settings API by construction — the operator can see
	 * the limiter in the code and has no way to touch it. This assertion is what makes the requirement
	 * true rather than intended.
	 */
	describe('the operator can reach every setting', () => {
		const KEYS = [
			'rateLimit.enabled',
			'rateLimit.trustedProxy',
			'rateLimit.maxTrackedOrigins',
			...NUMERIC_KEYS
		];

		it('catalogs all nine keys', () => {
			// Widened to string: the descriptor's key is a union of the declared settings, and comparing it
			// against a plain list is the whole point of this assertion.
			const catalogued = new Set<string>(
				SETTINGS_CATALOG.map((entry) => entry.key)
			);

			expect(KEYS.filter((key) => !catalogued.has(key))).toEqual([]);
		});

		it('files them under one group so they are found together', () => {
			const groups = new Set(
				SETTINGS_CATALOG.filter((entry) =>
					entry.key.startsWith('rateLimit.')
				).map((entry) => entry.group)
			);

			expect([...groups]).toEqual(['Rate limiting']);
		});

		// The switch gates the rest, so the form greys them out rather than offering numbers that do
		// nothing.
		it('hangs the tunable numbers off the master switch', () => {
			const dependent = SETTINGS_CATALOG.filter(
				(entry) =>
					entry.key.startsWith('rateLimit.') &&
					entry.key !== 'rateLimit.enabled'
			);

			expect(dependent).not.toHaveLength(0);
			for (const entry of dependent) {
				expect(entry.dependsOn).toBe('rateLimit.enabled');
			}
		});

		/*
		 * trustedProxy is the one setting here with a wrong answer in each direction, and an operator who
		 * reads only half of that will pick the one that takes their deployment down. Both directions have
		 * to be in the text they actually see.
		 */
		it('describes both failure directions of the proxy setting', () => {
			const entry = SETTINGS_CATALOG.find(
				(candidate) => candidate.key === 'rateLimit.trustedProxy'
			);

			const text = entry?.description.toLowerCase() ?? '';

			expect(entry).toBeDefined();
			// The deployment shape the operator has to recognise to choose correctly.
			expect(text).toContain('proxy');
			expect(text).toContain('directly exposed');
			// Leaving it wrongly ON: the bypass direction.
			expect(text).toContain('never limited');
			// Leaving it wrongly OFF: the outage direction.
			expect(text).toContain('one allowance');
		});
	});
});

describe('rate limit configuration in force', () => {
	describe('non-default allowances', () => {
		beforeEach(async () => {
			await bootstrap(import.meta.url);
			resetRateLimiter();
		});

		it('enforces whatever the operator set, not a compiled-in number', async () => {
			ApplicationConfig['rateLimit.strict.max'] = 2;

			const statuses = await flood('/token', ORIGIN_A, 3, { method: 'POST' });

			expect(refusals(statuses)).toBe(1);
		});

		it('follows the setting upward as well as downward', async () => {
			ApplicationConfig['rateLimit.strict.max'] = 9;

			const statuses = await flood('/token', ORIGIN_A, 9, { method: 'POST' });

			expect(refusals(statuses)).toBe(0);
		});
	});

	/*
	 * FR-008's off switch, and the property that makes it a safe incident lever: off has to be
	 * indistinguishable from absent, not merely permissive.
	 */
	describe('switched off', () => {
		const listeners: Array<[string, (...args: unknown[]) => void]> = [];

		function listen(channel: string) {
			const spy = mock();
			eventBus.on(channel, spy);
			listeners.push([channel, spy]);
			return spy;
		}

		beforeEach(async () => {
			await bootstrap(import.meta.url);
			resetRateLimiter();
			ApplicationConfig['rateLimit.enabled'] = false;
		});

		afterEach(() => {
			for (const [channel, spy] of listeners) {
				eventBus.off(channel, spy);
			}
			listeners.length = 0;
		});

		it('refuses nothing, however far past the allowance one origin goes', async () => {
			const statuses = await flood('/token', ORIGIN_A, 20, { method: 'POST' });

			expect(refusals(statuses)).toBe(0);
		});

		it('emits nothing on the rate-limited channel', async () => {
			const limited = listen('rate_limited');

			await flood('/token', ORIGIN_A, 20, { method: 'POST' });

			expect(limited).not.toHaveBeenCalled();
		});

		/*
		 * Nothing is counted while off, proven from the outside: if the disabled flood had been tallied,
		 * the allowance would already be spent when the switch comes back on. Asserting this through
		 * behaviour rather than by exporting the counter keeps the store's internals out of the API.
		 */
		it('counts nothing while off, so switching back on starts from a full allowance', async () => {
			await flood('/token', ORIGIN_A, 20, { method: 'POST' });

			ApplicationConfig['rateLimit.enabled'] = true;
			const afterOn = await flood(
				'/token',
				ORIGIN_A,
				ApplicationConfig['rateLimit.strict.max'] as number,
				{ method: 'POST' }
			);

			expect(refusals(afterOn)).toBe(0);
		});
	});
});
