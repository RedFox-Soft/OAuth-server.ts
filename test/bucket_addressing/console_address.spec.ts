import { afterAll, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, { clearSeededBuckets, seedBucket } from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { getBucketStore } from 'lib/adapters/index.js';
import { ISSUER } from 'lib/configs/env.js';
import { ensureAdminSeed } from 'lib/admin/seed.js';
import { DEFAULT_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.js';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.js';
import { bucketAddressFor } from 'lib/admin/ui/bucketAddress.js';
import { present, shaped } from 'test/shape.js';
import { Type } from '@sinclair/typebox';

// The one member read; a document without it (an error body) still reaches the toEqual and says so.
const Metadata = Type.Object({ issuer: Type.Optional(Type.String()) });

/* What the server renders into `window.PROPS.instanceHost`: ISSUER's host, so `e.ly` here (specs/101). */
const INSTANCE_HOST = new URL(ISSUER).host;

let subdomainBucketId: string;

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
		// A subdomain project needs no client to answer discovery, so it is created bare.
		subdomainBucketId = (
			await getBucketStore().create({
				name: 'Beta',
				slug: 'beta',
				subdomain: true,
				ownerGroupId: UNASSIGNED_GROUP_ID
			})
		)._id;
		forgetBucketAddresses();
	});

	afterAll(async () => {
		await clearSeededBuckets();
		await getBucketStore().destroy(subdomainBucketId);
		forgetBucketAddresses();
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
		expect(bucketAddressFor(present(bucket, 'bucket'), INSTANCE_HOST)).toEqual({
			kind: 'root'
		});
	});

	it('answers nothing at the slug the default bucket holds', async () => {
		expect((await discoveryAt('/default')).status).toBe(404);
	});

	/*
	 * The guard the case above cannot be: an example proves one bucket, and the defect is the bucket
	 * somebody did not think to check. Enumerated from the store rather than from a list in this file,
	 * so a form of address added later is covered the day a bucket has it.
	 */
	it('is served, for every bucket the console can list', async () => {
		const buckets = await getBucketStore().list();
		expect(buckets.length).toBeGreaterThan(2);
		const formsSeen = new Set<string>();

		for (const bucket of buckets) {
			const address = bucketAddressFor(bucket, INSTANCE_HOST);
			if (address.kind === 'none') continue;
			formsSeen.add(address.kind);

			// An own-origin bucket (a host, a subdomain) answers there, its issuer taking ISSUER's scheme.
			const { origin, issuer } =
				address.kind === 'host' || address.kind === 'subdomain'
					? {
							origin: `http://${address.host}`,
							issuer: `${new URL(ISSUER).protocol}//${address.host}`
						}
					: {
							origin: `http://localhost${address.kind === 'root' ? '' : address.path}`,
							issuer: `${ISSUER}${address.kind === 'root' ? '' : address.path}`
						};
			const response = await elysia.handle(
				new Request(`${origin}/.well-known/openid-configuration`)
			);

			expect({
				bucket: bucket._id,
				status: response.status
			}).toEqual({ bucket: bucket._id, status: 200 });
			expect({
				bucket: bucket._id,
				issuer: shaped(Metadata, await response.json()).issuer
			}).toEqual({ bucket: bucket._id, issuer });
		}
		/* The seeded buckets guarantee these three, so the walk cannot pass by checking nothing. */
		expect(
			['prefix', 'root', 'subdomain'].filter((kind) => !formsSeen.has(kind))
		).toEqual([]);
	});
});
