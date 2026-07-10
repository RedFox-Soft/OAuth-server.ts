import { describe, it, expect } from 'bun:test';
import Configuration from '../../lib/helpers/configuration.ts';

describe('Provider configuration', () => {
	// NOTE: feature enable flags and experiment acknowledgements are owned by ApplicationConfig
	// (flat dotted keys) and read from it directly — they are no longer carried on the nested
	// provider `features` config. The former "Unknown feature configuration" and "stable feature
	// ack no longer valid" checks validated that deprecated nested path and no longer apply.
	// Nested `features` still carries helper-function overrides, so the boolean-shape guard below
	// is retained.

	it('checks that a feature configuration is not a boolean', () => {
		expect(() => {
			new Configuration({
				features: {
					devInteractions: false
				}
			});
		}).toThrow(
			'Features are not enabled/disabled with a boolean value. See the documentation for more details.'
		);
		expect(() => {
			new Configuration({
				features: {
					devInteractions: true
				}
			});
		}).toThrow(
			'Features are not enabled/disabled with a boolean value. See the documentation for more details.'
		);
	});
});
