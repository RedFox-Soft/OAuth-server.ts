import { afterAll, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, { clearSeededBuckets, seedBucket } from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { ISSUER } from 'lib/configs/env.js';

const SLUG = 'acme';

/*
 * Dispatched into the app rather than fetched: the suite refuses any outbound request to an origin
 * nobody registered, and these URLs are this server's own.
 */
async function get(path: string) {
	return elysia.handle(new Request(`http://localhost${path}`));
}

async function doc(path: string) {
	return (await get(path)).json();
}

/**
 * @proves A named user bucket publishes authorization server metadata at both well-known locations
 * that apply to a path-bearing issuer, declaring itself as the issuer and advertising only its own
 * endpoints.
 */
describe('a named bucket publishes its own metadata', () => {
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
	 * The two locations are structurally different URLs for one issuer — OIDC Discovery appends the
	 * well-known segment to the issuer, RFC 8414 inserts it between host and path — and a client is
	 * entitled to use either. Serving one is the failure that passes locally and fails conformance.
	 */
	const locations = {
		'appended (OIDC Discovery 1.0 §4)': `/${SLUG}/.well-known/openid-configuration`,
		'inserted (RFC 8414 §3)': `/.well-known/openid-configuration/${SLUG}`
	};

	for (const [shape, path] of Object.entries(locations)) {
		it(`serves metadata at the ${shape} location`, async () => {
			const res = await get(path);

			expect(res.status).toBe(200);
			expect((await res.json()).issuer).toBe(`${ISSUER}/${SLUG}`);
		});
	}

	it('declares the same document at both locations', async () => {
		const appended = await doc(`/${SLUG}/.well-known/openid-configuration`);
		const inserted = await doc(`/.well-known/openid-configuration/${SLUG}`);

		expect(appended).toEqual(inserted);
	});

	it('advertises every endpoint beneath the bucket own issuer', async () => {
		const metadata = await doc(`/${SLUG}/.well-known/openid-configuration`);

		for (const [member, value] of Object.entries(metadata)) {
			if (!member.endsWith('_endpoint') || typeof value !== 'string') continue;
			expect(value).toStartWith(`${ISSUER}/${SLUG}/`);
		}
	});

	/*
	 * One key set for the whole server, advertised identically by every bucket: buckets are
	 * populations, not cryptographic boundaries. The one member deliberately exempt from the rule
	 * above, which is why it is asserted rather than left to the loop's `_endpoint` filter to skip.
	 */
	it('advertises the instance key set rather than one of its own', async () => {
		const metadata = await doc(`/${SLUG}/.well-known/openid-configuration`);

		expect(metadata.jwks_uri).toBe(`${ISSUER}/jwks`);
	});

	it('answers no metadata at an address naming no bucket', async () => {
		const res = await get('/nosuchbucket/.well-known/openid-configuration');

		expect(res.status).toBe(404);
	});
});
