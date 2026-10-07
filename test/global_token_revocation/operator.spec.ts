import { describe, it, beforeAll, afterEach, expect } from 'bun:test';

import { ApplicationConfig } from 'lib/configs/application.ts';
import { issuerFor } from 'lib/configs/issuer.ts';
import { elysia } from 'lib/index.ts';
import bootstrap from '../test_helper.js';
import {
	endpointOf,
	issSub,
	pathBucketWith,
	revoke,
	uniqueOrigin,
	upstreamProvider
} from './helpers.ts';

async function metadataOf(issuer: string, document: string) {
	const url = new URL(issuer);
	const path =
		url.pathname === '/'
			? `/.well-known/${document}`
			: `${url.pathname}/.well-known/${document}`;
	const response = await elysia.handle(new Request(`${url.origin}${path}`));
	return (await response.json()) as Record<string, unknown>;
}

/**
 * @proves An operator decides whether the endpoint exists at all: off, it is answered as any path this server
 * does not serve and no metadata mentions it; on, every bucket's metadata advertises it (spec 072, FR-002,
 * FR-003; User Story 2 scenario 11, User Story 3 scenario 4).
 */
describe('switching global token revocation on and off', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	afterEach(() => {
		ApplicationConfig['globalTokenRevocation.enabled'] = true;
	});

	it('answers the endpoint as an unserved path while the setting is off', async () => {
		const bucket = await pathBucketWith([
			upstreamProvider('corp', uniqueOrigin('off'))
		]);
		ApplicationConfig['globalTokenRevocation.enabled'] = false;

		const res = await revoke(endpointOf(bucket), {
			body: issSub('https://any.example', 'someone')
		});

		expect(res.status).toBe(404);
		expect(res.json).toHaveProperty('error', 'not_found');
	});

	it('omits the endpoint from discovery while the setting is off', async () => {
		const bucket = await pathBucketWith([]);
		ApplicationConfig['globalTokenRevocation.enabled'] = false;

		const metadata = await metadataOf(
			issuerFor(bucket),
			'openid-configuration'
		);

		expect(metadata).not.toHaveProperty('global_token_revocation_endpoint');
		expect(metadata).not.toHaveProperty(
			'global_token_revocation_endpoint_auth_methods_supported'
		);
	});

	it('advertises the bucket’s endpoint and its authentication method while the setting is on', async () => {
		const bucket = await pathBucketWith([]);

		const metadata = await metadataOf(
			issuerFor(bucket),
			'openid-configuration'
		);

		expect(metadata).toHaveProperty(
			'global_token_revocation_endpoint',
			endpointOf(bucket)
		);
		expect(metadata).toHaveProperty(
			'global_token_revocation_endpoint_auth_methods_supported',
			['private_key_jwt']
		);
	});

	it('advertises the endpoint in the OAuth authorization server metadata too', async () => {
		const bucket = await pathBucketWith([]);

		const metadata = await metadataOf(
			issuerFor(bucket),
			'oauth-authorization-server'
		);

		expect(metadata).toHaveProperty(
			'global_token_revocation_endpoint',
			endpointOf(bucket)
		);
	});
});
