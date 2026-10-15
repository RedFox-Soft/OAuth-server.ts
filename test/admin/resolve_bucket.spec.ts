import { describe, it, expect, beforeEach } from 'bun:test';
import { resolveBucketForRequest } from 'lib/admin/auth/resolveBucket.ts';
import {
	adapter,
	getBucketStore,
	getProtectedResourceStore,
	mcpClientPermissionStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import {
	ADMIN_CLIENT_ID,
	ADMIN_BUCKET_ID,
	DEFAULT_BUCKET_ID,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { ADMIN_MCP_CLIENT_SEED } from 'lib/consts/admin_seed.ts';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { DEFAULT_REQUEST_BUCKET } from 'lib/configs/issuer.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.ts';

/* Every case below signs in at the bare address, where rule 3 chooses among root-served buckets. */
const AT_ROOT = DEFAULT_REQUEST_BUCKET;

/* Its own identifier: declarations outlive a spec file, and two files declaring one identifier collide. */
const AUDIENCE = 'https://mcp.resolve.example/mcp';

/* A client identified by a document it hosts: it has no stored record, and so no bucket. */
const METADATA_DOCUMENT_CLIENT = 'https://app.resolve.example/client.json';

const stored: string[] = [];

/* A stored client record, as an administrator or the registration endpoint would have written it. */
async function storeClient(
	clientId: string,
	fields: Record<string, unknown> = {}
): Promise<void> {
	await adapter('Client').upsert(clientId, {
		clientId,
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://app.resolve.example/cb'],
		token_endpoint_auth_method: 'none',
		...fields
	});
	stored.push(clientId);
}

/* An application an administrator created in a bucket's Applications. */
async function applicationIn(clientId: string, bucketId: string) {
	await storeClient(clientId, { bucketId });
}

async function declaredResourceIn(bucketId: string) {
	await getProtectedResourceStore().create({
		namespace: ROOT_NAMESPACE,
		identifier: AUDIENCE,
		bucketId,
		name: 'Acme MCP',
		scopes: ['mcp:tools-basic']
	});
}

async function addressableBucket(name: string) {
	return getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name,
		slug: `${name.toLowerCase()}-${Math.random().toString(36).slice(2)}`
	});
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
		for (const clientId of stored.splice(0)) {
			await adapter('Client').destroy(clientId);
		}
		/* A permitted identity takes rule 4, so one case's permit must not answer another's. */
		for (const permission of await mcpClientPermissionStore.list()) {
			await mcpClientPermissionStore.destroy(permission._id);
		}
	});

	it('routes the admin client to the admin bucket', async () => {
		expect(
			await resolveBucketForRequest(ADMIN_CLIENT_ID, undefined, AT_ROOT)
		).toBe(ADMIN_BUCKET_ID);
	});

	it('routes the reserved agent client to the admin bucket', async () => {
		await storeClient(ADMIN_MCP_CLIENT_ID, { ...ADMIN_MCP_CLIENT_SEED });

		for (const resource of [undefined, MCP_RESOURCE]) {
			expect(
				await resolveBucketForRequest(ADMIN_MCP_CLIENT_ID, resource, AT_ROOT)
			).toBe(ADMIN_BUCKET_ID);
		}
	});

	it('routes an application to the bucket it was created in', async () => {
		await applicationIn('app-1', 'devs');

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
	 * Rule 3: a client belonging to no bucket reaches one through the declared resource the request
	 * names. Safe because an administrator authored that resource in a bucket they own — the parameter
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
			'HTTPS://mcp.resolve.example/mcp',
			'https://MCP.RESOLVE.EXAMPLE/mcp'
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
	 * Two named resources may belong to two buckets, and choosing one would be a guess about whose
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
	 * An application is never redirected by a parameter: the operator-established relationship is the
	 * stronger claim, and rule 2 runs first.
	 */
	it('lets an application keep its bucket even when a resource is named', async () => {
		await declaredResourceIn('acme-users');
		await applicationIn('app-1', 'devs');

		expect(await resolveBucketForRequest('app-1', AUDIENCE, AT_ROOT)).toBe(
			'devs'
		);
	});

	/*
	 * The administrative bucket is unreachable through rule 3, and this is the assertion that keeps it
	 * so. `${ISSUER}/mcp` is claimed by the built-in resource descriptor and refused at declaration
	 * time, so it can never be a declared resource pointing at the admin bucket — which is exactly the
	 * escalation `specs/024-admin-mcp-control-plane/research.md` D6 refused to open.
	 */
	it('cannot reach the admin bucket through a named resource', async () => {
		expect(
			await resolveBucketForRequest('unaffiliated', 'http://e.ly/mcp', AT_ROOT)
		).toBe('redfox');
	});

	/*
	 * An application on the Default bucket used to sit in a project that named no bucket at all
	 * (specs/098), and went on through the rules after rule 2. Belonging to the Default bucket must not
	 * end resolution early, or the migrations that recorded it would have moved people: so such a client
	 * resolves exactly as a client in no bucket does, whatever the request names.
	 */
	it('resolves an application on the Default bucket as it resolves a client in no bucket', async () => {
		await declaredResourceIn('acme-users');
		await applicationIn('on-default', DEFAULT_BUCKET_ID);
		for (const clientId of ['on-default', 'unaffiliated']) {
			await mcpClientPermissionStore.create({
				_id: clientId,
				kind: 'identifier'
			});
		}

		for (const resource of [undefined, AUDIENCE, MCP_RESOURCE]) {
			expect(
				await resolveBucketForRequest('on-default', resource, AT_ROOT)
			).toBe(await resolveBucketForRequest('unaffiliated', resource, AT_ROOT));
		}
		expect(
			await resolveBucketForRequest('on-default', undefined, AT_ROOT)
		).toBe('redfox');
		expect(await resolveBucketForRequest('on-default', AUDIENCE, AT_ROOT)).toBe(
			'acme-users'
		);
		expect(
			await resolveBucketForRequest('on-default', MCP_RESOURCE, AT_ROOT)
		).toBe(ADMIN_BUCKET_ID);
	});

	/*
	 * A client that registered itself at a bucket's own address is that bucket's client, and a resource
	 * the request names does not take it elsewhere.
	 */
	it('routes a client registered at a bucket address to that bucket', async () => {
		const bucket = await addressableBucket('Registrar');
		await declaredResourceIn('acme-users');
		await storeClient('dcr-at-bucket', {
			registeredDynamically: true,
			bucketId: bucket._id
		});

		for (const resource of [undefined, AUDIENCE]) {
			expect(
				await resolveBucketForRequest('dcr-at-bucket', resource, AT_ROOT)
			).toBe(bucket._id);
		}
	});

	/* One registered at the root belongs to no bucket, and resolves as a client in no bucket does. */
	it('resolves a client registered at the root through the remaining rules', async () => {
		await declaredResourceIn('acme-users');
		await storeClient('dcr-at-root', { registeredDynamically: true });

		expect(
			await resolveBucketForRequest('dcr-at-root', undefined, AT_ROOT)
		).toBe('redfox');
		expect(
			await resolveBucketForRequest('dcr-at-root', AUDIENCE, AT_ROOT)
		).toBe('acme-users');
	});

	it('resolves a client identified by its metadata document through the remaining rules', async () => {
		await declaredResourceIn('acme-users');

		expect(
			await resolveBucketForRequest(
				METADATA_DOCUMENT_CLIENT,
				undefined,
				AT_ROOT
			)
		).toBe('redfox');
		expect(
			await resolveBucketForRequest(METADATA_DOCUMENT_CLIENT, AUDIENCE, AT_ROOT)
		).toBe('acme-users');
	});

	/*
	 * The squatting route, closed. A declaration in a bucket with an address of its own is that
	 * bucket's namespace, and the root address reads only the root's — so a tenant declaring somebody
	 * else's MCP server in its own bucket steers nobody who signs in anywhere else.
	 */
	it('never reaches a declaration in an addressable bucket from the root address', async () => {
		const bucket = await addressableBucket('Squatter');
		await getProtectedResourceStore().create({
			namespace: bucket._id,
			identifier: AUDIENCE,
			bucketId: bucket._id,
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
