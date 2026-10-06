import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import { connect, scim, scimBucket, type Connected } from './helpers.ts';

/**
 * @proves An identity system learns from the discovery endpoints what this SCIM service supports, and that
 * it never accepts a password (spec 070, User Story 1, scenarios 1–2).
 */
describe('SCIM discovery', () => {
	let c: Connected;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'scim' });
		c = await connect(await scimBucket());
	});

	it('declares patch and filtering supported and bulk, sort, ETags and password change unsupported', async () => {
		const { status, json } = await scim(
			'GET',
			`${c.base}/ServiceProviderConfig`,
			{ token: c.token }
		);

		expect(status).toBe(200);
		expect(json).toMatchObject({
			patch: { supported: true },
			filter: { supported: true, maxResults: 1000 },
			bulk: { supported: false },
			sort: { supported: false },
			etag: { supported: false },
			changePassword: { supported: false },
			authenticationSchemes: [{ type: 'oauthbearertoken' }]
		});
	});

	it('describes no password attribute in any schema', async () => {
		const { status, json } = await scim('GET', `${c.base}/Schemas`, {
			token: c.token
		});

		expect(status).toBe(200);
		const names = JSON.stringify(json).toLowerCase();
		expect(names).toContain('"name":"username"');
		expect(names).not.toContain('"name":"password"');
	});
});
