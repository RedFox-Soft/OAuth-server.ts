import { describe, it, expect, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { configStore } from 'lib/adapters/index.js';
import { expectUnservedEquivalent } from '../feature_gate/helpers.js';
import { readSettings, saveSettings, superAdminCookie } from './helpers.js';

/**
 * @proves A submission the server could not boot with changes neither what is stored nor what the
 * running server does — applying settings does not give a refused change a second way in.
 */
describe('a settings submission the server could not start with', () => {
	let cookie: string;

	beforeEach(async () => {
		await bootstrap(import.meta.url);
		await configStore.set({});
		cookie = await superAdminCookie();
	});

	/*
	 * Registration management without registration is one of the cross-key invariants the boot
	 * validator enforces, so a server holding this combination is a server that would refuse to start.
	 * Before this feature a refusal cost nothing beyond the 422; now that a save reaches the running
	 * process, a refusal that let half a submission through would be a way to put a live server into a
	 * state it could never be restarted into.
	 */
	it('is refused, and leaves the capability it would have enabled unserved', async () => {
		const res = await saveSettings(cookie, {
			'registrationManagement.enabled': true
		});
		expect(res.status).toBe(422);

		const state = await readSettings(cookie);
		expect(state.values['registrationManagement.enabled']).toBe(false);
		expect(state.notInForceKeys).toEqual([]);
		expect(state.pendingRestartKeys).toEqual([]);

		await expectUnservedEquivalent('/reg/some-client', { method: 'GET' });
	});

	it('stores nothing when it is refused', async () => {
		await saveSettings(cookie, { 'registrationManagement.enabled': true });

		expect(await configStore.get()).toEqual({});
	});

	it('is refused when a value does not match what its setting accepts', async () => {
		const res = await saveSettings(cookie, { 'par.enabled': 'yes please' });
		expect(res.status).toBe(422);

		const state = await readSettings(cookie);
		expect(state.values['par.enabled']).toBe(false);
	});
});
