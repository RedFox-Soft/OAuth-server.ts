import { describe, it, expect } from 'bun:test';
import { validateConfiguration } from 'lib/configs/configuration.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';

/*
 * The error store's bounds, tested against the pure validator — the single definition the
 * administrative PUT reaches through validateEffectiveConfig, so what is pinned here is what a
 * super-admin cannot persist.
 *
 * The bounds are what keep a switched-on store from growing without limit, so every case below is
 * checked with the capability *off*: a deployment must not be able to save a nonsensical bound while
 * the feature is disabled and have it take effect on the restart that enables it.
 */
const withErrorStore = (overrides: Record<string, unknown>) => ({
	...ApplicationConfig,
	...overrides
});

describe('errorStore configuration validation', () => {
	it('accepts the shipped defaults', () => {
		expect(() => validateConfiguration({ ...ApplicationConfig })).not.toThrow();
	});

	const bounds = [
		'errorStore.retentionDays',
		'errorStore.maxGroups',
		'errorStore.samplesPerGroup',
		'errorStore.queueDepth'
	];

	for (const key of bounds) {
		it(`rejects ${key} at zero`, () => {
			expect(() => validateConfiguration(withErrorStore({ [key]: 0 }))).toThrow(
				`${key} must be a positive integer`
			);
		});

		it(`rejects ${key} negative`, () => {
			expect(() =>
				validateConfiguration(withErrorStore({ [key]: -1 }))
			).toThrow(`${key} must be a positive integer`);
		});

		/*
		 * A fractional bound is refused rather than truncated. Silently flooring 2.5 samples to 2 would
		 * mean the store kept a different number than the operator asked for, which is the kind of
		 * disagreement that is only ever discovered while reading an incomplete fault.
		 */
		it(`rejects ${key} fractional`, () => {
			expect(() =>
				validateConfiguration(withErrorStore({ [key]: 1.5 }))
			).toThrow(`${key} must be a positive integer`);
		});

		it(`accepts ${key} at one`, () => {
			expect(() =>
				validateConfiguration(withErrorStore({ [key]: 1 }))
			).not.toThrow();
		});
	}

	it('rejects an unknown origin capture level', () => {
		expect(() =>
			validateConfiguration(
				withErrorStore({ 'errorStore.originCaptureLevel': 'hashed' })
			)
		).toThrow('errorStore.originCaptureLevel must be one of');
	});

	for (const level of ['omitted', 'anonymized', 'full']) {
		it(`accepts the ${level} origin capture level`, () => {
			expect(() =>
				validateConfiguration(
					withErrorStore({ 'errorStore.originCaptureLevel': level })
				)
			).not.toThrow();
		});
	}

	// The bounds hold whether the capability is on or off, so the enabled case must pass the same set.
	it('applies the same bounds with the capability enabled', () => {
		expect(() =>
			validateConfiguration(
				withErrorStore({
					'errorStore.enabled': true,
					'errorStore.maxGroups': 0
				})
			)
		).toThrow('errorStore.maxGroups must be a positive integer');
	});
});
