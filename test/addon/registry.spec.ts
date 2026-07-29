import { describe, it, expect, beforeAll } from 'bun:test';

import { setAddonBaseline } from '../addon_baseline.js';

// Warm the provider/model graph before importing the addon index. The index
// pulls account.js -> grant.js -> base_token.js; base_token participates in a
// cycle through formats/jwt.js -> provider that only resolves cleanly when the
// provider is the entry point. Importing lib/provider first initializes the graph
// in the right order (without starting the HTTP server that lib/index would).
import '../../lib/event_bus.js';

import {
	addons,
	deviceInfo,
	rarForCodeResponse
} from '../../lib/addon/index.js';

// The global afterEach in test/preload.ts calls addons.reset() after every test.
// These specs deliberately do NOT define a local reset — they prove the global
// hook is what keeps overrides from leaking between tests.

const fakeCtx = {
	ip: '203.0.113.7',
	get(header: string) {
		return header === 'user-agent' ? 'default-agent' : undefined;
	}
};

describe('addon override registry', () => {
	// This spec does not call bootstrap(), so clear any baseline a prior spec set
	// before relying on default resolution.
	beforeAll(() => setAddonBaseline(undefined));

	it('resolves an override registered after the module was imported (dynamic call-time resolution)', () => {
		// deviceInfo was imported at the top of the file; the override is registered
		// here, after import. Dynamic resolution means the accessor still picks it up.
		addons.override({
			deviceInfo: () => ({ ip: 'overridden', ua: 'overridden' })
		});

		expect(deviceInfo(fakeCtx)).toEqual({ ip: 'overridden', ua: 'overridden' });
	});

	it('resolves the default again in the next test (global reset cleared the override, no leakage)', () => {
		// No override registered in this test. If the previous test's override
		// leaked, this would return the sentinel. The global afterEach reset means
		// it returns the addon default computed from the context.
		expect(deviceInfo(fakeCtx)).toEqual({
			ip: '203.0.113.7',
			ua: 'default-agent'
		});
	});

	it('preserves must-override refusal: an un-overridden RAR transform throws', () => {
		expect(() => rarForCodeResponse({}, {})).toThrow(
			'features.richAuthorizationRequests.rarForCodeResponse not implemented'
		);
	});

	it('restores the default after an explicit reset', () => {
		addons.override({ deviceInfo: () => ({ ip: 'x', ua: 'x' }) });
		expect(deviceInfo(fakeCtx)).toEqual({ ip: 'x', ua: 'x' });

		addons.reset();
		expect(deviceInfo(fakeCtx)).toEqual({
			ip: '203.0.113.7',
			ua: 'default-agent'
		});
	});
});
