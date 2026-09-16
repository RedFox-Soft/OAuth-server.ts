import { afterAll, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, { clearSeededBuckets, seedBucket } from '../test_helper.js';
import { elysia } from 'lib/index.js';

const SLUG = 'acme';

/**
 * @proves Every endpoint a bucket's metadata advertises is served at the address it advertises.
 */
describe('a bucket metadata', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await seedBucket({
			bucketId: 'acme-bucket',
			slug: SLUG,
			clientId: 'acme-app',
			accountId: 'bob'
		});
	});

	afterAll(async () => {
		await clearSeededBuckets();
	});

	/*
	 * A completeness guard, enumerated from the document the server actually builds rather than from a
	 * list someone wrote down. It closes the claim no example closes: the endpoint somebody advertised
	 * and forgot to mount. A client following discovery has no other way to find out than a 404.
	 */
	it('advertises no endpoint that is not served', async () => {
		const doc = (await (
			await elysia.handle(
				new Request(`http://localhost/${SLUG}/.well-known/openid-configuration`)
			)
		).json()) as Record<string, unknown>;

		const missing: string[] = [];
		for (const [member, value] of Object.entries(doc)) {
			if (!member.endsWith('_endpoint') || typeof value !== 'string') continue;
			const path = new URL(value).pathname;
			for (const method of ['GET', 'POST']) {
				const res = await elysia.handle(
					new Request(`http://localhost${path}`, { method })
				);
				if (res.status !== 404) break;
				if (method === 'POST') missing.push(`${member} ${path}`);
			}
		}

		expect(missing).toEqual([]);
	});
});
