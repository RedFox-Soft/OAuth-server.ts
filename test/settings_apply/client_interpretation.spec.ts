import { describe, it, expect, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { configStore } from 'lib/adapters/index.js';
import { send } from '../feature_gate/helpers.js';
import { saveSettings, superAdminCookie } from './helpers.js';

const JWT = 'application/token-introspection+jwt';

const basic = Buffer.from('introspector:secret').toString('base64');

function introspect(): Promise<Response> {
	return send('/token/introspect', {
		method: 'POST',
		headers: {
			authorization: `Basic ${basic}`,
			accept: JWT,
			'content-type': 'application/x-www-form-urlencoded'
		},
		body: 'token=not-a-real-token'
	});
}

/**
 * @proves A client is interpreted under the settings in force when it is resolved, not under the
 * settings that were in force the last time somebody resolved it.
 */
describe('a client resolved after a settings change', () => {
	let cookie: string;

	beforeEach(async () => {
		await bootstrap(import.meta.url);
		await configStore.set({});
		cookie = await superAdminCookie();
		await saveSettings(cookie, { 'introspection.enabled': true });
	});

	/*
	 * The first call is the trap being laid: it resolves the client while the capability that gives
	 * its metadata field meaning is off, and whatever that produced is what a memo would still be
	 * holding one save later. Signed responses are the observable difference because the decision is
	 * made from the client's own metadata, not from the flag alone.
	 */
	it('is read under the setting in force at resolution time, not at its last resolution', async () => {
		const before = await introspect();
		expect(before.status).toBe(200);
		expect(before.headers.get('content-type')).toContain('application/json');

		await saveSettings(cookie, { 'jwtIntrospection.enabled': true });

		const after = await introspect();
		expect(after.status).toBe(200);
		expect(after.headers.get('content-type')).toContain(JWT);
	});
});
