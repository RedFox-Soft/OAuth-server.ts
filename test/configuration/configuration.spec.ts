import { describe, it, expect } from 'bun:test';
import { validateConfiguration } from 'lib/configs/configuration.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';

describe('Provider configuration', () => {
	// Feature enable flags and experiment acknowledgements are owned by ApplicationConfig
	// (flat dotted keys). Behavior-function overrides are owned by the addon registry.
	// The nested `features` config object therefore no longer exists: a `features` key present in a
	// configuration is inert — it is never consulted, so it neither takes effect nor throws.
	it('ignores a nested features configuration object', () => {
		const withNested = {
			...ApplicationConfig,
			features: { introspection: { enabled: false } }
		};

		expect(() => validateConfiguration(withNested)).not.toThrow();
		// The flat key is what decides, and the nested object did not override it.
		expect(validateConfiguration(withNested).grantTypes).toEqual(
			validateConfiguration({ ...ApplicationConfig }).grantTypes
		);
	});

	// The validator must not mutate what it is handed: the admin settings API checks a candidate
	// configuration with it before deciding whether to persist that candidate.
	it('does not mutate the configuration it validates', () => {
		const config = structuredClone({ ...ApplicationConfig });
		const before = structuredClone(config);

		validateConfiguration(config);

		expect(config).toEqual(before);
	});
});

/*
 * The DPoP nonce rules, tested here rather than through HTTP because there is no HTTP path to these
 * states — and that is the point of testing them at all.
 *
 * configs/application.ts provisions a usable secret before it validates anything, so a running server
 * can never hold a configuration these rules reject. The rules exist so that the guarantee does not
 * rest on provisioning having run: the validator is a pure function of its argument, so it can be
 * handed the impossible configuration directly. If provisioning is ever reordered, moved, or made
 * conditional, these cases are what notices.
 */
describe('Provider configuration: DPoP nonces', () => {
	const usable = Buffer.alloc(32, 7);

	it('rejects requiring a nonce with no usable secret', () => {
		expect(() =>
			validateConfiguration({
				...ApplicationConfig,
				'dpop.enabled': true,
				'dpop.requireNonce': true,
				'dpop.nonceSecret': undefined
			})
		).toThrow(/dpop\.nonceSecret/);
	});

	it('names the setting that created the requirement', () => {
		// An operator reading this has to know which switch to look at, not merely that something is
		// wrong with the secret.
		expect(() =>
			validateConfiguration({
				...ApplicationConfig,
				'dpop.enabled': true,
				'dpop.requireNonce': true,
				'dpop.nonceSecret': undefined
			})
		).toThrow(/dpop\.requireNonce/);
	});

	it('rejects a secret that is not 32 bytes, whether or not a nonce is required', () => {
		for (const requireNonce of [true, false]) {
			expect(() =>
				validateConfiguration({
					...ApplicationConfig,
					'dpop.enabled': true,
					'dpop.requireNonce': requireNonce,
					'dpop.nonceSecret': Buffer.alloc(16, 0)
				})
			).toThrow(/32-byte/);
		}
	});

	it('rejects a secret of the shape a storage round trip produces', () => {
		// Asserted because the whole point of this case is a value the type system says cannot exist —
		// the declared type is byte material, and a document store hands back this instead. That gap
		// between declared and actual is the defect itself, so it cannot be expressed without overriding
		// the type, and a runtime check is the only thing that can catch it.
		const roundTripped = {
			type: 'Buffer',
			data: new Array(32).fill(0)
		} as unknown as Uint8Array;

		expect(() =>
			validateConfiguration({
				...ApplicationConfig,
				'dpop.enabled': true,
				'dpop.nonceSecret': roundTripped
			})
		).toThrow(/32-byte/);
	});

	it('accepts a usable secret with nonces required', () => {
		expect(() =>
			validateConfiguration({
				...ApplicationConfig,
				'dpop.enabled': true,
				'dpop.requireNonce': true,
				'dpop.nonceSecret': usable
			})
		).not.toThrow();
	});

	// Deliberately not a rule. With DPoP off no proof is ever examined, so the requirement is inert and
	// cannot fail; the admin UI already presents it as dependent on DPoP. Pinned so that a later reader
	// sees a decision rather than an oversight.
	it('accepts requiring a nonce while DPoP itself is disabled', () => {
		expect(() =>
			validateConfiguration({
				...ApplicationConfig,
				'dpop.enabled': false,
				'dpop.requireNonce': true,
				'dpop.nonceSecret': undefined
			})
		).not.toThrow();
	});

	// Replay detection records proof identifiers through the ReplayDetection model and never touches the
	// nonce secret. The two were conflated in the task this feature came from; this is the pin that
	// stops a later reader re-conflating them.
	it('never makes replay detection depend on the nonce secret', () => {
		for (const allowReplay of [true, false]) {
			expect(() =>
				validateConfiguration({
					...ApplicationConfig,
					'dpop.enabled': true,
					'dpop.requireNonce': false,
					'dpop.allowReplay': allowReplay,
					'dpop.nonceSecret': undefined
				})
			).not.toThrow();
		}
	});
});
