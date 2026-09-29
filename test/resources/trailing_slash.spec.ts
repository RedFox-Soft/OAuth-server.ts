import { beforeAll, describe, expect, it } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';

import bootstrap from '../test_helper.ts';
import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.ts';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { resourceRoutes } from 'lib/admin/resources/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getBucketStore,
	getProjectStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { decode } from 'lib/helpers/jwt.ts';
import { sessionFor, personalGroupId } from '../admin_session.ts';
import { answered } from '../admin/answered.ts';
import { Type } from '@sinclair/typebox';
import { shaped } from 'test/shape.ts';

const SLUG = 'slashco';
const WITH_SLASH = 'https://mcp.slash.example/mcp/';
const WITHOUT_SLASH = 'https://mcp.slash.example/mcp';

const admin = treaty(
	new Elysia({ normalize: false }).use(resolveAdmin).use(resourceRoutes)
);

const TokenAnswer = Type.Object({
	access_token: Type.Optional(Type.String()),
	error: Type.Optional(Type.String())
});

async function machineToken(resource: string) {
	const response = await elysia.handle(
		new Request(`${ISSUER}/${SLUG}/token`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				authorization: `Basic ${btoa('slash-machine:slash-machine-secret')}`
			},
			body: new URLSearchParams({ grant_type: 'client_credentials', resource })
		})
	);
	return shaped(TokenAnswer, await response.json());
}

let cookie: string;
let projectId: string;

/**
 * @proves A resource declared with a significant trailing slash is a different audience from its
 * slash-free sibling, end to end: it is issued tokens only under its exact spelling, and the console
 * addresses it by that spelling.
 */
describe('a resource declared with a significant trailing slash', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'trailing_slash' });
		await ensureAdminSeed();
		forgetBucketAddresses();

		const user = await getUserStore(ADMIN_BUCKET_ID).create(
			`slash-${Math.random()}@x.io`,
			'hash',
			['project_admin']
		);
		cookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
		const ownerGroupId = await personalGroupId(user._id);
		const bucket = await getBucketStore().create({
			ownerGroupId,
			name: 'Slash users',
			slug: SLUG
		});
		const project = await getProjectStore().create({
			ownerGroupId,
			name: 'Slash',
			slug: `slash-${Math.random().toString(36).slice(2)}`
		});
		await getProjectStore().update(project._id, {
			bucketId: bucket._id,
			clientIds: ['slash-machine']
		});
		projectId = project._id;

		const created = await admin.admin.api
			.projects({ id: projectId })
			.resources.post(
				{
					identifier: WITH_SLASH,
					name: 'Slash MCP',
					scopes: ['slash:read'],
					trailingSlashSignificant: true
				},
				{ headers: { cookie } }
			);
		expect(created.status).toBe(201);
	});

	it('is issued a token under its exact spelling', async () => {
		const answer = await machineToken(WITH_SLASH);

		expect(decode(answer.access_token ?? '').payload.aud).toBe(WITH_SLASH);
	});

	it('is not issued a token under the slash-free spelling', async () => {
		const answer = await machineToken(WITHOUT_SLASH);

		expect(answer.error).toBe('invalid_target');
	});

	it('is read by its exact spelling', async () => {
		const read = await admin.admin.api
			.projects({ id: projectId })
			.resources({ resourceId: encodeURIComponent(WITH_SLASH) })
			.get({ headers: { cookie } });

		expect(answered(read.data).identifier).toBe(WITH_SLASH);
	});

	it('is updated by its exact spelling', async () => {
		const amended = await admin.admin.api
			.projects({ id: projectId })
			.resources({ resourceId: encodeURIComponent(WITH_SLASH) })
			.patch({ name: 'Slash MCP v2' }, { headers: { cookie } });

		expect(amended.status).toBe(200);
	});
});
