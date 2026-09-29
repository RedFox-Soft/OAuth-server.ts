import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.ts';
import { getBucketKeysStore } from 'lib/adapters/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import {
	addresses,
	keySetAt,
	machineToken,
	publishedKeys,
	tenant
} from './tenants.ts';

const {
	slug: PATH_SLUG,
	host: HOST,
	pathOrigin: PATH_ORIGIN,
	hostOrigin: HOST_ORIGIN,
	pathClient,
	hostClient
} = addresses('ep');

const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

async function discoveryAt(origin: string) {
	const response = await elysia.handle(
		new Request(`${origin}/.well-known/openid-configuration`)
	);
	return (await response.json()) as { jwks_uri?: string };
}

function kidsOf(set: { keys: Array<Record<string, unknown>> }) {
	return set.keys.map((key) => key.kid).sort();
}

let pathBucketId: string;

/**
 * @proves Each addressable bucket publishes a key set of its own under its own address, holding its
 * public keys and nothing else — no private member, no other bucket's key, and none at the root —
 * while an address naming no bucket publishes no keys at all.
 */
describe("a bucket's key set", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'bucket_keys' });
		forgetBucketAddresses();
		pathBucketId = await tenant({ slug: PATH_SLUG }, pathClient);
		await tenant({ host: HOST }, hostClient);
		// A bucket's first key is created the first time the bucket signs.
		await machineToken(PATH_ORIGIN, pathClient);
		await machineToken(HOST_ORIGIN, hostClient);
	});

	it('is advertised under the path bucket own address', async () => {
		expect((await discoveryAt(PATH_ORIGIN)).jwks_uri).toBe(
			`${PATH_ORIGIN}/jwks`
		);
	});

	it('is advertised under the host bucket own address', async () => {
		expect((await discoveryAt(HOST_ORIGIN)).jwks_uri).toBe(
			`${HOST_ORIGIN}/jwks`
		);
	});

	it('lists exactly the keys the bucket holds', async () => {
		const stored = (await getBucketKeysStore().listByBucket(pathBucketId))
			.map((key) => key.kid)
			.sort();

		expect(kidsOf(await publishedKeys(`${PATH_ORIGIN}/jwks`))).toEqual(stored);
	});

	it('carries no private member of any key', async () => {
		const { body } = await keySetAt(`${PATH_ORIGIN}/jwks`);

		const set = JSON.parse(body) as { keys: Array<Record<string, unknown>> };
		for (const key of set.keys) {
			for (const member of PRIVATE_MEMBERS) {
				expect(key).not.toHaveProperty(member);
			}
		}
	});

	it('shares no key with another bucket', async () => {
		const path = kidsOf(await publishedKeys(`${PATH_ORIGIN}/jwks`));
		const host = kidsOf(await publishedKeys(`${HOST_ORIGIN}/jwks`));

		expect(path.filter((kid) => host.includes(kid))).toEqual([]);
	});

	it('leaves the root issuer advertising the instance key set, holding none of a bucket key', async () => {
		expect((await discoveryAt(ISSUER)).jwks_uri).toBe(`${ISSUER}/jwks`);

		const root = kidsOf(await publishedKeys(`${ISSUER}/jwks`));
		const path = kidsOf(await publishedKeys(`${PATH_ORIGIN}/jwks`));
		expect(root.filter((kid) => path.includes(kid))).toEqual([]);
	});

	it('is not found at an address naming no bucket, never falling back to the root keys', async () => {
		expect((await keySetAt(`${ISSUER}/nosuchbucket/jwks`)).status).toBe(404);
	});

	it('is not found at a tenant host naming no bucket', async () => {
		expect((await keySetAt('http://nobody-here.e.ly/jwks')).status).toBe(404);
	});
});
