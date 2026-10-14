/*
 * Every issuer tells clients which languages its pages can be shown in.
 */

import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, { seedBucket } from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.js';

const DOCUMENTS = ['openid-configuration', 'oauth-authorization-server'];

// The root issuer, a bucket addressed by a path, and a bucket addressed by a hostname of its own.
const ISSUERS: Array<[string, (document: string) => string]> = [
	['the root issuer', (document) => `http://localhost/.well-known/${document}`],
	[
		'a path-addressed bucket',
		(document) => `http://localhost/talk/.well-known/${document}`
	],
	[
		'a host-addressed bucket',
		(document) => `http://talk-host.example/.well-known/${document}`
	]
];

/**
 * @proves A client can learn from either discovery document of any issuer which languages the sign-in pages
 * can be shown in, so it can ask for one the server speaks (OIDC Discovery §3, RFC 8414 §2).
 */
describe('the languages an issuer advertises', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await seedBucket({
			bucketId: 'talk-bucket',
			slug: 'talk',
			clientId: 'talk-app',
			accountId: 'talker'
		});
		await getBucketStore().create({
			_id: 'talk-host-bucket',
			name: 'Talk by host',
			host: 'talk-host.example',
			ownerGroupId: 'unassigned'
		});
		forgetBucketAddresses();
	});

	for (const [issuer, url] of ISSUERS) {
		for (const document of DOCUMENTS) {
			it(`lists English, Russian and Simplified Chinese in the ${document} document of ${issuer}`, async () => {
				const response = await elysia.handle(new Request(url(document)));
				const metadata = (await response.json()) as Record<string, unknown>;

				expect(response.status).toBe(200);
				expect(metadata.ui_locales_supported).toEqual(['en', 'ru', 'zh-Hans']);
				expect(metadata).not.toHaveProperty('claims_locales_supported');
			});
		}
	}
});
