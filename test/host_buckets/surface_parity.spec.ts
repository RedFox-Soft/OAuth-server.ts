import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap from '../test_helper.ts';
import { getBucketStore, resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { elysia } from 'lib/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { INSTANCE_PLANE_PREFIXES } from 'lib/plugins/instancePlane.ts';

const TENANT_HOST = 'parity.e.ly';

/*
 * The instance-wide surfaces, enumerated from the route table the application actually mounts rather
 * than from a list somebody keeps in step by hand. The defect this closes is the surface somebody
 * forgot to exclude, and no example-based case can prove an absence.
 */
function mountedRoutes(): string[] {
	const routes = (elysia as unknown as { routes?: { path: string }[] }).routes;
	return (routes ?? []).map((route) => route.path);
}

function at(path: string, host: string) {
	return elysia.handle(
		new Request(`http://${host}${path}`, { redirect: 'manual' })
	);
}

/**
 * @proves The surfaces that belong to the instance are not served at a tenant's address, and the
 * surfaces a tenant needs are — checked over the mounted route table rather than over a list, because
 * the defect in both directions is the route somebody forgot.
 */
describe('which surfaces answer at a bucket host (US1)', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'host_buckets' });
		resetAdminMemoryStores();
		forgetBucketAddresses();
		await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Parity',
			host: TENANT_HOST
		});
	});

	it('serves no instance-wide surface at a bucket host, for every one the application mounts', async () => {
		const instanceRoutes = mountedRoutes().filter((path) =>
			INSTANCE_PLANE_PREFIXES.some(
				(prefix) => path === prefix || path.startsWith(`${prefix}/`)
			)
		);

		/* If this is empty the guard below proves nothing, which is the way this kind of case fails
		 * silently. */
		expect(instanceRoutes.length).toBeGreaterThan(0);

		const served: string[] = [];
		for (const path of instanceRoutes) {
			/* Only the routes with no path parameters can be requested as written; a parameterised one
			 * would need a value this case has no opinion about. */
			if (path.includes(':') || path.includes('*')) continue;
			const response = await at(path, TENANT_HOST);
			if (response.status !== 404) served.push(`${path} → ${response.status}`);
		}

		expect(served).toEqual([]);
	});

	it('serves the administrative console at the canonical host', async () => {
		/* The other half of the same claim: the guard must refuse a tenant's address without refusing
		 * the address the console is actually reached at. */
		const response = await at('/admin/login', 'e.ly');

		expect(response.status).not.toBe(404);
	});

	it('serves the end-user surfaces a sign-in needs at a bucket host', async () => {
		/* A bucket whose people cannot reach the pages that sign them in is not addressable in any sense
		 * that matters. `/verify-email` is one such standing page. */
		const response = await at('/verify-email', TENANT_HOST);

		expect(response.status).not.toBe(404);
	});
});
