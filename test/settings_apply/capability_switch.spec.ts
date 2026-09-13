import { describe, it, expect, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { configStore } from 'lib/adapters/index.js';
import { expectUnservedEquivalent, send } from '../feature_gate/helpers.js';
import {
	discoveryDocument,
	saveSettings,
	superAdminCookie
} from './helpers.js';

const form = { 'content-type': 'application/x-www-form-urlencoded' };

/*
 * Pushed authorization requests, because the capability ships switched off, its endpoint is gated,
 * and discovery advertises it — so one setting exercises every surface a capability has, from a state
 * a deployment really starts in.
 */
const PAR = '/par';

/**
 * @proves A capability an administrator switches through the management API governs the very next
 * request this server answers, in both directions and on every surface that describes it.
 */
describe('a capability switched through the management API', () => {
	let cookie: string;

	beforeEach(async () => {
		await bootstrap(import.meta.url);
		await configStore.set({});
		cookie = await superAdminCookie();
	});

	it('serves its endpoint on the next request after it is switched on', async () => {
		await expectUnservedEquivalent(PAR, { method: 'POST', headers: form });

		const saved = await saveSettings(cookie, { 'par.enabled': true });
		expect(saved.status).toBe(200);

		const res = await send(PAR, {
			method: 'POST',
			headers: form,
			body: 'client_id=client'
		});
		/*
		 * Any answer but 404 settles it: what is under test is whether the path exists, and an
		 * unauthenticated request to a real endpoint is refused for a reason of its own.
		 */
		expect(res.status).not.toBe(404);
	});

	it('answers its endpoint as an unserved path from the next request after it is switched off', async () => {
		await saveSettings(cookie, { 'par.enabled': true });

		const saved = await saveSettings(cookie, { 'par.enabled': false });
		expect(saved.status).toBe(200);

		await expectUnservedEquivalent(PAR, { method: 'POST', headers: form });
	});

	it('advertises the capability while it is on and in neither document once it is off', async () => {
		await saveSettings(cookie, { 'par.enabled': true });
		const on = await discoveryDocument();
		expect(on).toHaveProperty('pushed_authorization_request_endpoint');

		await saveSettings(cookie, { 'par.enabled': false });
		const off = await discoveryDocument();
		expect(off).not.toHaveProperty('pushed_authorization_request_endpoint');
	});

	it('reports the saved value as running once it has been applied', async () => {
		const res = await saveSettings(cookie, { 'par.enabled': true });
		const body = (await res.json()) as {
			appliedKeys: string[];
			pendingRestartKeys: string[];
			notInForceKeys: string[];
		};

		expect(body.appliedKeys).toEqual(['par.enabled']);
		expect(body.pendingRestartKeys).toEqual([]);
		expect(body.notInForceKeys).toEqual([]);
	});
});
