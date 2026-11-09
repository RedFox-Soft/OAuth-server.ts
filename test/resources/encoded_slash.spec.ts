import { beforeAll, describe, expect, it } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';

import bootstrap from '../test_helper.ts';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { resourceRoutes } from 'lib/admin/resources/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { sessionFor, personalGroupId } from '../admin_session.ts';
import { answered } from '../admin/answered.ts';
import { createAdministrator } from '../administrators.ts';

const NESTED = 'https://mcp.encoded.example/tools/mcp';
const ENCODED = 'https://mcp.encoded.example/tools%2Fmcp';

const admin = treaty(
	new Elysia({ normalize: false }).use(resolveAdmin).use(resourceRoutes)
);

let cookie: string;
let bucketId: string;

/**
 * @proves An administrator addresses a declared resource by its exact identifier, even when two
 * identifiers differ only in a slash and its percent-encoded form: Elysia leaves an encoded slash in a
 * path parameter undecoded and so cannot tell them apart, and the console must.
 */
describe('a resource whose identifier holds an encoded slash', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'trailing_slash' });
		await ensureAdminSeed();
		forgetBucketAddresses();

		const user = await createAdministrator(
			'plain',
			`encoded-${Math.random()}@x.io`
		);
		cookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
		const bucket = await getBucketStore().create({
			ownerGroupId: await personalGroupId(user._id),
			name: 'Encoded users',
			slug: 'encodedco'
		});
		bucketId = bucket._id;

		for (const identifier of [NESTED, ENCODED]) {
			const created = await admin.admin.api
				.projects({ id: bucketId })
				.resources.post(
					{ identifier, name: identifier, scopes: ['tools:read'] },
					{ headers: { cookie } }
				);
			expect(created.status).toBe(201);
		}
	});

	for (const identifier of [NESTED, ENCODED]) {
		it(`is read by its exact spelling: ${identifier}`, async () => {
			const read = await admin.admin.api
				.projects({ id: bucketId })
				.resources({ resourceId: encodeURIComponent(identifier) })
				.get({ headers: { cookie } });

			expect(answered(read.data).identifier).toBe(identifier);
		});
	}

	it('is updated by its exact spelling, leaving its sibling alone', async () => {
		const amended = await admin.admin.api
			.projects({ id: bucketId })
			.resources({ resourceId: encodeURIComponent(ENCODED) })
			.patch({ name: 'Encoded v2' }, { headers: { cookie } });
		const sibling = await admin.admin.api
			.projects({ id: bucketId })
			.resources({ resourceId: encodeURIComponent(NESTED) })
			.get({ headers: { cookie } });

		expect(answered(amended.data).name).toBe('Encoded v2');
		expect(answered(sibling.data).name).toBe(NESTED);
	});
});
