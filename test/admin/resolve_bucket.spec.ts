import { describe, it, expect, beforeEach } from 'bun:test';
import { resolveBucketForRequest } from 'lib/admin/auth/resolveBucket.ts';
import {
	getBucketStore,
	getProjectStore,
	getProtectedResourceStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import {
	ADMIN_CLIENT_ID,
	ADMIN_BUCKET_ID,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { DEFAULT_REQUEST_BUCKET } from 'lib/configs/issuer.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.ts';

/* Every case below signs in at the bare address, where rule 3 chooses among root-served buckets. */
const AT_ROOT = DEFAULT_REQUEST_BUCKET;

const AUDIENCE = 'https://mcp.acme.example/mcp';

async function declaredResourceIn(bucketId: string) {
	const project = await getProjectStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: 'Acme',
		slug: `acme-${Math.random()}`,
		bucketId
	});
	await getProtectedResourceStore().create({
		namespace: ROOT_NAMESPACE,
		identifier: AUDIENCE,
		projectId: project._id,
		name: 'Acme MCP',
		scopes: ['mcp:tools-basic']
	});
	return project;
}

/**
 * @proves The five rules that decide which bucket a request signs a user into, in order,
 * including that a named resource can select among an operator options but never create one.
 */
describe('resolveBucketForRequest', () => {
	beforeEach(async () => {
		resetAdminMemoryStores();
		const store = getProtectedResourceStore();
		for (const resource of await store.list()) {
			await store.destroy(resource.namespace, resource.identifier);
		}
	});

	it('routes the admin client to the admin bucket', async () => {
		expect(
			await resolveBucketForRequest(ADMIN_CLIENT_ID, undefined, AT_ROOT)
		).toBe(ADMIN_BUCKET_ID);
	});

	it('routes an assigned client to its project bucket', async () => {
		await getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'P',
			slug: `p-${Math.random()}`,
			bucketId: 'devs',
			clientIds: ['app-1']
		});
		expect(await resolveBucketForRequest('app-1', undefined, AT_ROOT)).toBe(
			'devs'
		);
	});

	it('falls back to redfox for an unassigned or missing client', async () => {
		expect(await resolveBucketForRequest('unknown', undefined, AT_ROOT)).toBe(
			'redfox'
		);
		expect(await resolveBucketForRequest(undefined, undefined, AT_ROOT)).toBe(
			'redfox'
		);
	});

	/*
	 * Rule 3: a client belonging to no project reaches one through the declared resource the request
	 * names. Safe because an administrator authored that resource in a project they own — the parameter
	 * selects among an operator's options and cannot create one.
	 */
	it('derives the bucket from a declared resource the request names', async () => {
		await declaredResourceIn('acme-users');

		expect(
			await resolveBucketForRequest('unaffiliated', AUDIENCE, AT_ROOT)
		).toBe('acme-users');
	});

	it('canonicalizes the named resource, so a spelling variant resolves alike', async () => {
		await declaredResourceIn('acme-users');

		for (const named of [
			`${AUDIENCE}/`,
			'HTTPS://mcp.acme.example/mcp',
			'https://MCP.ACME.EXAMPLE/mcp'
		]) {
			expect(
				await resolveBucketForRequest('unaffiliated', named, AT_ROOT)
			).toBe('acme-users');
		}
	});

	it('ignores a resource nobody declared', async () => {
		expect(
			await resolveBucketForRequest(
				'unaffiliated',
				'https://nobody.example.com/mcp',
				AT_ROOT
			)
		).toBe('redfox');
	});

	/*
	 * Two named resources may belong to two projects, and choosing one would be a guess about whose
	 * accounts to offer. Falling back is the answer that cannot be quietly wrong.
	 */
	it('derives nothing from two named resources', async () => {
		await declaredResourceIn('acme-users');

		expect(
			await resolveBucketForRequest(
				'unaffiliated',
				[AUDIENCE, 'https://other.example.com/mcp'],
				AT_ROOT
			)
		).toBe('redfox');
	});

	it('accepts a single-element array, which is how the parameter often arrives', async () => {
		await declaredResourceIn('acme-users');

		expect(
			await resolveBucketForRequest('unaffiliated', [AUDIENCE], AT_ROOT)
		).toBe('acme-users');
	});

	/*
	 * An assigned client is never redirected by a parameter: the operator-established relationship is
	 * the stronger claim, and rule 2 runs first.
	 */
	it('lets an assigned client keep its project bucket even when a resource is named', async () => {
		await declaredResourceIn('acme-users');
		await getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Other',
			slug: `other-${Math.random()}`,
			bucketId: 'devs',
			clientIds: ['app-1']
		});

		expect(await resolveBucketForRequest('app-1', AUDIENCE, AT_ROOT)).toBe(
			'devs'
		);
	});

	/*
	 * The administrative bucket is unreachable through rule 3, and this is the assertion that keeps it
	 * so. `${ISSUER}/mcp` is claimed by the built-in resource descriptor and refused at declaration
	 * time, so it can never be a declared resource pointing at the admin project — which is exactly the
	 * escalation `specs/024-admin-mcp-control-plane/research.md` D6 refused to open.
	 */
	it('cannot reach the admin bucket through a named resource', async () => {
		expect(
			await resolveBucketForRequest('unaffiliated', 'http://e.ly/mcp', AT_ROOT)
		).toBe('redfox');
	});

	/*
	 * The squatting route, closed. A declaration in a bucket with an address of its own is that
	 * bucket's namespace, and the root address reads only the root's — so a tenant declaring somebody
	 * else's MCP server in its own bucket steers nobody who signs in anywhere else.
	 */
	it('never reaches a declaration in an addressable bucket from the root address', async () => {
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Squatter',
			slug: `squat-${Math.random().toString(36).slice(2)}`
		});
		const project = await getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Squatter',
			slug: `squatter-${Math.random()}`,
			bucketId: bucket._id
		});
		await getProtectedResourceStore().create({
			namespace: bucket._id,
			identifier: AUDIENCE,
			projectId: project._id,
			name: 'Somebody else',
			scopes: ['mcp:tools-basic']
		});

		expect(
			await resolveBucketForRequest('unaffiliated', AUDIENCE, AT_ROOT)
		).toBe('redfox');
		expect(
			await resolveBucketForRequest('unaffiliated', AUDIENCE, {
				_id: bucket._id,
				slug: bucket.slug
			})
		).toBe(bucket._id);
	});
});
