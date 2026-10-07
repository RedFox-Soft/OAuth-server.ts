import { describe, it, beforeAll, expect } from 'bun:test';

import { ApplicationConfig } from 'lib/configs/application.js';
import bootstrap from '../test_helper.js';
import { expectUnservedEquivalent } from '../feature_gate/helpers.js';
import { connect, scim, scimBucket, type Connected } from './helpers.ts';

/**
 * @proves An identity system learns from the discovery endpoints what this SCIM service supports, that it
 * never accepts a password, and that a resource it does not serve is a 404 in SCIM's shape — while a
 * disabled SCIM surface is indistinguishable from no surface at all (spec 070, User Story 1, scenarios 1–2).
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

	it('answers a resource it does not serve, such as /Bulk, with a SCIM 404 a directory can read', async () => {
		for (const base of [c.base, '/scim/v2']) {
			const { status, json, headers } = await scim('GET', `${base}/Bulk`, {
				token: c.token
			});

			expect(status).toBe(404);
			expect(headers.get('content-type')).toStartWith('application/scim+json');
			expect(json).toMatchObject({
				schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
				status: '404'
			});
		}
	});

	it('answers that path as any unserved one while SCIM is off, so nothing announces the surface', async () => {
		ApplicationConfig['scim.enabled'] = false;
		try {
			await expectUnservedEquivalent(`${c.base}/Bulk`, { method: 'GET' });
		} finally {
			ApplicationConfig['scim.enabled'] = true;
		}
	});
});
