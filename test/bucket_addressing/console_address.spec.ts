import { afterAll, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, { clearSeededBuckets, seedBucket } from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { getBucketStore } from 'lib/adapters/index.js';
import { ISSUER } from 'lib/configs/env.js';
import { ensureAdminSeed } from 'lib/admin/seed.js';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.js';
import { bucketAddressFor } from 'lib/admin/ui/bucketAddress.js';

async function discoveryAt(prefix: string) {
	return elysia.handle(
		new Request(`http://localhost${prefix}/.well-known/openid-configuration`)
	);
}

/**
 * @proves The address the console lists a bucket at is one the server answers, so an operator who
 * points a client at what the Buckets table shows reaches that bucket.
 */
describe('the address the console reports for a bucket', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'bucket_addressing' });
		await ensureAdminSeed();
		await seedBucket({
			bucketId: 'acme-bucket',
			slug: 'acme',
			clientId: 'acme-app',
			accountId: 'bob'
		});
		await seedBucket({
			bucketId: 'quiet-bucket',
			clientId: 'default-app',
			accountId: 'ana'
		});
	});

	afterAll(async () => {
		await clearSeededBuckets();
	});

	/*
	 * The reported defect, named as the operator met it. The default bucket holds the slug `default` —
	 * it must, because a session cookie is named after something — and the console rendered any slug it
	 * found, so the Buckets table advertised `/default`. That is the one column an operator copies when
	 * pointing a client at a bucket, and the path answers 404.
	 */
	it('reports the root for the default bucket rather than the slug it holds', async () => {
		const bucket = await getBucketStore().find(DEFAULT_BUCKET_ID);

		expect(bucket?.slug).toBe('default');
		expect(bucketAddressFor(bucket!)).toEqual({ kind: 'root' });
	});

	it('answers nothing at the slug the default bucket holds', async () => {
		expect((await discoveryAt('/default')).status).toBe(404);
	});

	/*
	 * The guard the case above cannot be: an example proves one bucket, and the defect is the bucket
	 * somebody did not think to check. Enumerated from the store rather than from a list in this file,
	 * so a bucket state added later is covered the day it exists.
	 */
	it('is served, for every bucket the console can list', async () => {
		const buckets = await getBucketStore().list();
		expect(buckets.length).toBeGreaterThan(2);

		for (const bucket of buckets) {
			const address = bucketAddressFor(bucket);
			if (address.kind === 'none') continue;

			const prefix = address.kind === 'root' ? '' : address.path;
			const response = await discoveryAt(prefix);

			expect({
				bucket: bucket._id,
				status: response.status
			}).toEqual({ bucket: bucket._id, status: 200 });
			expect({
				bucket: bucket._id,
				issuer: (await response.json()).issuer
			}).toEqual({ bucket: bucket._id, issuer: `${ISSUER}${prefix}` });
		}
	});
});
