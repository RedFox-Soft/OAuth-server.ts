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
