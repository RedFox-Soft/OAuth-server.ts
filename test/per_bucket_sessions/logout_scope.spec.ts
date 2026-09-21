import { afterAll, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, {
	clearSeededBuckets,
	seedBucket,
	type Setup
} from '../test_helper.js';
import { elysia } from 'lib/index.js';

/**
 * @proves A sign-out ends the sign-in of the population the client belongs to, so a client of one
 * user bucket cannot sign an end user out of another.
 */
describe('signing out across buckets', () => {
	let setup: Setup;
	let held: string;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
		await seedBucket({
			bucketId: 'acme',
			slug: 'acme',
			clientId: 'acme-app',
			accountId: 'bob'
		});
		held = await setup.login({ accountId: 'ana' });
	});

	afterAll(async () => {
		await clearSeededBuckets();
	});

	const endSession = (clientId: string) =>
		elysia.handle(
			new Request(
				`http://localhost/logout?client_id=${encodeURIComponent(clientId)}`,
				{ headers: { cookie: held } }
			)
		);

	it('refuses to end a sign-in for a client of another bucket', async () => {
		const response = await endSession('acme-app');

		expect(response.status).toBe(400);
	});

	it('offers to end the sign-in for a client of the bucket addressed', async () => {
		const response = await endSession('default-app');

		expect(response.status).toBe(200);
	});
});
