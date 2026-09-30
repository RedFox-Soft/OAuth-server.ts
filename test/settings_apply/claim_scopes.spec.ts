import { describe, it, expect, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { configStore } from 'lib/adapters/index.js';
import {
	discoveryDocument,
	saveSettings,
	superAdminCookie
} from './helpers.js';

const BASE = {
	acr: null,
	sid: null,
	auth_time: null,
	iss: null,
	openid: ['sub']
};

/**
 * @proves An operator defines which claims a scope releases from the management API, the definition
 * is advertised the moment it is saved, and a definition the server could not interpret is refused
 * rather than stored.
 */
describe('scopes defined by the claims they release', () => {
	let cookie: string;

	beforeEach(async () => {
		await bootstrap(import.meta.url);
		await configStore.set({});
		cookie = await superAdminCookie();
	});

	it('advertises a scope and its claims as soon as the definition is saved', async () => {
		const res = await saveSettings(cookie, {
			claims: { ...BASE, profile: ['name', 'given_name'] }
		});
		expect(res.status).toBe(200);

		const discovery = await discoveryDocument();
		expect(discovery.scopes_supported).toContain('profile');
		expect(discovery.claims_supported).toEqual(
			expect.arrayContaining(['name', 'given_name'])
		);

		expect((await saveSettings(cookie, { claims: BASE })).status).toBe(200);
	});

	it('refuses a scope whose definition is neither a claim nor a list of claim names', async () => {
		const res = await saveSettings(cookie, {
			claims: { ...BASE, profile: 'name' }
		});

		expect(res.status).toBe(422);
	});

	it('refuses a list of claim names holding something that is not a name', async () => {
		const res = await saveSettings(cookie, {
			claims: { ...BASE, profile: ['name', 42] }
		});

		expect(res.status).toBe(422);
	});

	it('refuses a definition without the openid scope', async () => {
		const { openid: _openid, ...withoutOpenid } = BASE;
		const res = await saveSettings(cookie, { claims: withoutOpenid });

		expect(res.status).toBe(422);
	});
});
