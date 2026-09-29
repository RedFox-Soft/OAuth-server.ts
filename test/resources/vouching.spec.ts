import { afterEach, beforeEach, describe, expect, it } from 'bun:test';
import { Elysia } from 'elysia';

import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { resourceRoutes } from 'lib/admin/resources/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ensurePersonalGroup } from 'lib/admin/groups/personal.ts';
import {
	getProjectStore,
	getProtectedResourceStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { ISSUER } from 'lib/configs/env.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.ts';
import { assertNoPendingInterceptors, mock } from '../fetch_mock.ts';
import { sessionFor } from '../admin_session.ts';
import {
	challengeWithMetadata,
	serveResourceMetadata
} from './resource_metadata.ts';

const app = new Elysia({ normalize: false })
	.use(resolveAdmin)
	.use(resourceRoutes);

let cookie: string;
let projectId: string;

async function declared(identifier: string) {
	await getProtectedResourceStore().create({
		namespace: ROOT_NAMESPACE,
		identifier,
		projectId,
		name: identifier,
		scopes: ['mcp:tools-basic']
	});
}

async function vouching(identifier: string) {
	const response = await app.handle(
		new Request(
			`http://e.ly/admin/api/projects/${projectId}/resources/${encodeURIComponent(identifier)}/vouching`,
			{ headers: { cookie } }
		)
	);
	const text = await response.text();
	return { raw: text, body: JSON.parse(text) as Record<string, unknown> };
}

function unique(label: string) {
	return `https://${label}-${Math.random().toString(36).slice(2, 8)}.example/mcp`;
}

/**
 * @proves An operator can see, for each declared resource, whether its own published metadata
 * currently vouches for it and which discovery step found it — or why not — without the report ever
 * carrying text the resource returned.
 */
describe("a declared resource's published metadata", () => {
	beforeEach(async () => {
		await ensureAdminSeed();
		const user = await getUserStore(ADMIN_BUCKET_ID).create(
			`vouch-${Math.random()}@x.io`,
			'hash',
			['project_admin']
		);
		const group = await ensurePersonalGroup(user._id, user.email);
		cookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
		projectId = (
			await getProjectStore().create({
				ownerGroupId: group._id,
				name: 'Vouched',
				slug: `vouched-${Math.random().toString(36).slice(2)}`
			})
		)._id;
	});

	afterEach(() => {
		assertNoPendingInterceptors();
	});

	it('is reported vouched through the challenge header', async () => {
		const identifier = unique('challenge');
		await declared(identifier);
		challengeWithMetadata(identifier);

		const { body } = await vouching(identifier);

		expect(body).toEqual({
			status: 'vouched',
			step: 'challenge',
			expectedIssuer: ISSUER
		});
	});

	it('is reported vouched through the path-inserted well-known address', async () => {
		const identifier = unique('inserted');
		await declared(identifier);
		serveResourceMetadata(identifier);

		expect((await vouching(identifier)).body).toMatchObject({
			status: 'vouched',
			step: 'path_inserted'
		});
	});

	it('is reported vouched through the root well-known address', async () => {
		const identifier = unique('root');
		await declared(identifier);
		serveResourceMetadata(identifier, {}, { atRoot: true });

		expect((await vouching(identifier)).body).toMatchObject({
			status: 'vouched',
			step: 'root'
		});
	});

	it('falls through to the well-known steps when a challenge names no metadata', async () => {
		const identifier = unique('bare-challenge');
		await declared(identifier);
		mock(new URL(identifier).origin)
			.intercept({ path: '/mcp' })
			.reply(401, '', {
				headers: { 'www-authenticate': 'Bearer realm="mcp"' }
			});
		serveResourceMetadata(identifier);

		expect((await vouching(identifier)).body).toMatchObject({
			status: 'vouched',
			step: 'path_inserted'
		});
	});

	it('is reported not vouched, naming the issuer, when the metadata lists another', async () => {
		const identifier = unique('elsewhere');
		await declared(identifier);
		serveResourceMetadata(identifier, {
			authorization_servers: ['https://someone-else.example']
		});

		expect((await vouching(identifier)).body).toEqual({
			status: 'not_vouched',
			step: 'path_inserted',
			reason: 'issuer_not_listed',
			expectedIssuer: ISSUER
		});
	});

	it('is reported not vouched when the metadata describes another resource', async () => {
		const identifier = unique('other');
		await declared(identifier);
		serveResourceMetadata(identifier, {
			resource: 'https://another.example/mcp'
		});

		expect((await vouching(identifier)).body).toMatchObject({
			status: 'not_vouched',
			reason: 'resource_mismatch'
		});
	});

	it('is reported not checked when the resource is on a private address', async () => {
		await declared('https://10.2.3.4/mcp');

		expect((await vouching('https://10.2.3.4/mcp')).body).toMatchObject({
			status: 'not_checked',
			reason: 'blocked_address'
		});
	});

	it('carries no text the resource returned', async () => {
		const identifier = unique('marker');
		await declared(identifier);
		serveResourceMetadata(identifier, {
			authorization_servers: ['https://MARKER-FROM-THE-RESOURCE.example'],
			resource_name: 'MARKER-FROM-THE-RESOURCE'
		});

		const { raw } = await vouching(identifier);

		expect(raw).not.toContain('MARKER-FROM-THE-RESOURCE');
	});
});
