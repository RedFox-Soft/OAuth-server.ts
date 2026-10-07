import { describe, it, expect, beforeEach, afterAll } from 'bun:test';

import bootstrap from '../test_helper.js';
import { configStore } from 'lib/adapters/index.js';
import {
	discoveryDocument,
	saveSettings,
	superAdminCookie
} from './helpers.js';

/**
 * @proves The `groups` scope and claim are advertised on every instance — including one whose operator saved
 * a claims definition before the scope existed, which replaces the default whole (spec 071, User Story 2
 * scenario 6).
 */
describe('the built-in groups scope', () => {
	let cookie: string;

	beforeEach(async () => {
		await bootstrap(import.meta.url);
		await configStore.set({});
		cookie = await superAdminCookie();
	});

	afterAll(async () => {
		await configStore.set({});
	});

	it('is advertised when a saved claims definition does not mention it', async () => {
		const res = await saveSettings(cookie, {
			claims: {
				acr: null,
				sid: null,
				auth_time: null,
				iss: null,
				openid: ['sub']
			}
		});
		expect(res.status).toBe(200);

		const discovery = await discoveryDocument();
		expect(discovery.scopes_supported).toContain('groups');
		expect(discovery.claims_supported).toContain('groups');
	});
});
