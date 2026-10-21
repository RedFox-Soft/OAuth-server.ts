import { describe, beforeAll, beforeEach, it, expect } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { shaped } from 'test/shape.js';
import { adminCookie, defaultBucket } from '../end_user_lifecycle/fixtures.ts';
import { admin } from '../provisioning/helpers.ts';
import {
	defaultBucketWith,
	upstreamProvider
} from '../global_token_revocation/helpers.ts';
import { declareApi } from '../assertion_grants/helpers.js';

const PROVIDER = `/admin/api/projects/${DEFAULT_BUCKET_ID}/federation/legacy`;
const API = 'https://api.trust.acme.example/';

const Presented = Type.Object({
	plainAssertions: Type.Object({
		applications: Type.Array(Type.String()),
		apis: Type.Array(
			Type.Object({
				identifier: Type.String(),
				scopes: Type.Array(Type.String())
			})
		)
	})
});

function trust(
	applications: string[],
	apis: { identifier: string; scopes: string[] }[]
) {
	return { plainAssertions: { applications, apis } };
}

/**
 * @proves An administrator can trust a provider for plain assertions only for this project's confidential
 * applications that hold the JWT bearer grant, and only for APIs and scopes the project declares; and no two
 * providers sharing an issuer can both be trusted.
 */
describe("trusting a provider's plain assertions", () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await defaultBucket();
		cookie = await adminCookie();
		await declareApi(API, ['profile.read', 'profile.write']);
	});

	beforeEach(async () => {
		await defaultBucketWith([
			upstreamProvider('legacy', 'https://legacy.idp.test', {
				acceptsGlobalTokenRevocation: undefined
			})
		]);
	});

	it('saves a trust naming the project’s applications and APIs and reads it back in the same words', async () => {
		const res = await admin(
			'PATCH',
			PROVIDER,
			cookie,
			trust(['migrator'], [{ identifier: API, scopes: ['profile.read'] }])
		);

		expect(res.status).toBe(200);
		expect(shaped(Presented, res.body).plainAssertions).toEqual({
			applications: ['migrator'],
			apis: [{ identifier: API, scopes: ['profile.read'] }]
		});
	});

	for (const [what, applications] of [
		['an application the project does not have', ['nobody']],
		['an application that does not authenticate', ['spa']],
		['an application without the JWT bearer grant', ['no-grant']]
	] as const) {
		it(`refuses ${what}`, async () => {
			const res = await admin(
				'PATCH',
				PROVIDER,
				cookie,
				trust(
					[...applications],
					[{ identifier: API, scopes: ['profile.read'] }]
				)
			);

			expect(res.status).toBe(422);
		});
	}

	it('refuses an API the project has not declared', async () => {
		const res = await admin(
			'PATCH',
			PROVIDER,
			cookie,
			trust(
				['migrator'],
				[{ identifier: 'https://undeclared.example/', scopes: [] }]
			)
		);

		expect(res.status).toBe(422);
	});

	it('refuses a scope the API does not declare', async () => {
		const res = await admin(
			'PATCH',
			PROVIDER,
			cookie,
			trust(['migrator'], [{ identifier: API, scopes: ['admin'] }])
		);

		expect(res.status).toBe(422);
	});

	it('refuses to trust a second provider with the same issuer', async () => {
		await defaultBucketWith([
			upstreamProvider('legacy', 'https://legacy.idp.test', {
				acceptsGlobalTokenRevocation: undefined
			}),
			upstreamProvider('legacy-twin', 'https://legacy.idp.test', {
				acceptsGlobalTokenRevocation: undefined,
				acceptsIdentityAssertions: true
			})
		]);

		const res = await admin(
			'PATCH',
			PROVIDER,
			cookie,
			trust(['migrator'], [{ identifier: API, scopes: ['profile.read'] }])
		);

		expect(res.status).toBe(409);
	});
});
