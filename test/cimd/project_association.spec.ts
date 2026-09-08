import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getBucketStore,
	getProjectStore,
	getProtectedResourceStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';

/*
 * Which project a client with no prior relationship belongs to, and therefore whose end-users it can
 * sign in.
 *
 * This is the question `specs/024-admin-mcp-control-plane/research.md` D6 left open, and the answer is
 * derived from the declared protected resource the request names. What makes that safe — and what made
 * D6's rejected version unsafe — is who authored the resource: an administrator declared it in a
 * project they own, and that project's bucket is their own choice. An attacker cannot declare a
 * resource, so the parameter selects among an operator's options rather than creating one.
 *
 * Driven through the real authorization dance, on the pattern of
 * `test/admin/interactions_bucket.spec.ts`: a successful login hands back to the authorization
 * pipeline (a redirect), a failed bucket lookup re-renders the form (400).
 */

const PASSWORD = 'correct horse battery';
const AUDIENCE = 'https://mcp.acme.example/mcp';

async function login(
	query: Parameters<typeof agent.auth.get>[0]['query'],
	username: string
) {
	const { response } = await agent.auth.get({ query });
	const location = getHeader(response, 'location');
	const uid = location.split('/')[2];
	const cookie = response.headers.get('set-cookie');
	if (!cookie) throw new Error('expected an interaction cookie from /auth');

	const submitted = await agent
		.ui({ uid })
		.login.post({ username, password: PASSWORD }, { headers: { cookie } });
	return submitted.response.status;
}

function authParams(extra: Record<string, unknown> = {}) {
	const auth = new AuthorizationRequest({
		client_id: 'unaffiliated',
		scope: 'openid'
	});
	return { ...auth.params, ...extra };
}

describe('bucket resolution for a client that belongs to no project', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'project_association' });
		resetAdminMemoryStores();
		await ensureAdminSeed();

		const bucket = await getBucketStore().create({
			name: 'Acme users',
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		const project = await getProjectStore().create({
			name: 'Acme',
			slug: 'acme',
			ownerGroupId: UNASSIGNED_GROUP_ID,
			bucketId: bucket._id
		});
		await getProtectedResourceStore().create({
			_id: AUDIENCE,
			projectId: project._id,
			name: 'Acme MCP',
			scopes: ['mcp:tools-basic']
		});

		/* Exists only in the project's own bucket, never in the default one. */
		await getUserStore(bucket._id).create(
			'acme-only@x.io',
			await Bun.password.hash(PASSWORD)
		);
		/* And the mirror image, so a wrong answer in either direction fails. */
		await getUserStore().create(
			'default-only@x.io',
			await Bun.password.hash(PASSWORD)
		);
	});

	it('signs in the project bucket user when the request names the project resource', async () => {
		expect(
			await login(authParams({ resource: AUDIENCE }), 'acme-only@x.io')
		).toBe(303);
	});

	it('does not reach the default bucket while a resource is named', async () => {
		expect(
			await login(authParams({ resource: AUDIENCE }), 'default-only@x.io')
		).toBe(400);
	});

	/*
	 * Without a resource there is nothing to derive from, so the existing fallback stands unchanged.
	 * Asserted because the new rule must be additive: a deployment that names no resource has to behave
	 * exactly as it did.
	 */
	it('falls back to the default bucket when no resource is named', async () => {
		expect(await login(authParams(), 'default-only@x.io')).toBe(303);
		expect(await login(authParams(), 'acme-only@x.io')).toBe(400);
	});

	/*
	 * A resource nobody declared is refused at the authorization endpoint before any of this, so it can
	 * never become a way to probe for buckets.
	 */
	it('refuses a resource nobody declared', async () => {
		const { response } = await agent.auth.get({
			query: authParams({ resource: 'https://nobody.example.com/mcp' })
		});

		const location = getHeader(response, 'location');
		expect(location).toContain('error=invalid_target');
	});
});
