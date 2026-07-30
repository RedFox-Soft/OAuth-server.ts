import { describe, it, beforeEach, afterEach, expect, mock } from 'bun:test';

import bootstrap from '../test_helper.js';
import { eventBus } from 'lib/event_bus.js';
import { expectUnservedEquivalent, send } from './helpers.js';

// Every channel a refused request could plausibly land in if the gate leaked into the routed error
// path. All of them must stay silent (FR-004).
const CAPABILITY_CHANNELS = [
	'introspection.error',
	'userinfo.error',
	'end_session.error',
	'end_session_confirm.error',
	'revocation.error',
	'device_authorization.error',
	'backchannel_authentication.error',
	'pushed_authorization_request.error'
] as const;

describe('feature gate — observability', () => {
	const listeners: Array<[string, (...args: unknown[]) => void]> = [];

	function listen(channel: string) {
		const spy = mock();
		eventBus.on(channel, spy);
		listeners.push([channel, spy]);
		return spy;
	}

	beforeEach(async () => {
		await bootstrap(import.meta.url);
	});

	afterEach(() => {
		for (const [channel, spy] of listeners) {
			eventBus.off(channel, spy);
		}
		listeners.length = 0;
	});

	it('emits exactly one feature_disabled signal naming the path and the flag', async () => {
		const disabled = listen('feature_disabled');

		await send('/token/introspect', {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: 'token=whatever'
		});

		expect(disabled).toHaveBeenCalledTimes(1);

		const [payload] = disabled.mock.calls[0] ?? [];
		expect(payload).toEqual({
			method: 'POST',
			path: '/token/introspect',
			flag: 'introspection.enabled'
		});
	});

	it('emits no capability-specific error and no generic server_error', async () => {
		const serverError = listen('server_error');
		const capability = CAPABILITY_CHANNELS.map(
			(channel) => [channel, listen(channel)] as const
		);

		await send('/userinfo', { method: 'GET' });
		await send('/par', { method: 'POST' });
		await send('/backchannel', { method: 'POST' });

		for (const [channel, spy] of capability) {
			expect(spy, `${channel} must stay silent`).toHaveBeenCalledTimes(0);
		}
		expect(serverError).toHaveBeenCalledTimes(0);
	});

	// FR-004b: the signal is server-side only. Attaching a subscriber must not perturb the response.
	it('leaves the response identical when a subscriber is attached', async () => {
		listen('feature_disabled');

		await expectUnservedEquivalent('/userinfo', { method: 'GET' });
	});
});
