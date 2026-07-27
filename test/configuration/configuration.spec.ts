import { describe, it, expect } from 'bun:test';
import Configuration from '../../lib/helpers/configuration.ts';

describe('Provider configuration', () => {
	// Feature enable flags and experiment acknowledgements are owned by ApplicationConfig
	// (flat dotted keys). Behavior-function overrides are owned by the addon registry.
	// The nested `features` config object therefore no longer exists: any `features` key
	// passed to the provider configuration is not merged and is silently ignored (it is not
	// among the retained data defaults), so it neither takes effect nor throws.

	it('ignores a nested features configuration object', () => {
		expect(() => {
			new Configuration({
				features: {
					introspection: false
				}
			});
		}).not.toThrow();
	});
});
