import { describe, it, beforeAll, expect } from 'bun:test';

import { getProjectStore } from 'lib/adapters/index.js';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import bootstrap from '../test_helper.js';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { admin } from '../provisioning/helpers.ts';
import {
	defaultScimBucket,
	provider,
	scim,
	scimBucket,
	slugOf
} from './helpers.ts';

/**
 * @proves A SCIM client discovers where to get a token for a bucket's SCIM endpoint from the endpoint's
 * RFC 9728 metadata, and nobody can declare that endpoint as a resource of their own (spec 070, FR-016).
 */
describe('a bucket’s SCIM protected-resource metadata', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'scim' });
	});

	it('names the bucket’s issuer and the scim scope, at the inserted path of a path-addressed bucket', async () => {
		const bucket = await scimBucket();

		const res = await scim(
			'GET',
			`/.well-known/oauth-protected-resource/${slugOf(bucket)}/scim/v2`
		);

		expect(res.status).toBe(200);
		expect(res.json).toEqual({
			resource: `http://e.ly/${slugOf(bucket)}/scim/v2`,
			authorization_servers: [`http://e.ly/${slugOf(bucket)}`],
			scopes_supported: ['scim'],
			bearer_methods_supported: ['header'],
			resource_name: 'SCIM provisioning'
		});
	});

	it('names the server’s own issuer for the default bucket at the bare path', async () => {
		await defaultScimBucket([provider('corp')]);

		const res = await scim(
			'GET',
			'/.well-known/oauth-protected-resource/scim/v2'
		);

		expect(res.status).toBe(200);
		expect(res.json).toMatchObject({
			resource: 'http://e.ly/scim/v2',
			authorization_servers: ['http://e.ly']
		});
	});

	it('refuses to declare a bucket’s SCIM endpoint as a protected resource', async () => {
		const cookie = await adminCookie();
		const bucket = await scimBucket();
		const project = await getProjectStore().create({
			name: 'Declarer',
			slug: `declarer-${Math.random().toString(36).slice(2, 8)}`,
			ownerGroupId: UNASSIGNED_GROUP_ID
		});

		const res = await admin(
			'POST',
			`/admin/api/projects/${project._id}/resources`,
			cookie,
			{
				identifier: `http://e.ly/${slugOf(bucket)}/scim/v2`,
				name: 'Squatter',
				scopes: ['scim']
			}
		);

		expect(res.status).toBe(409);
	});
});
