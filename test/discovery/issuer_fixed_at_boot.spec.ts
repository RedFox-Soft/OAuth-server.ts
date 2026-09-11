import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { ISSUER } from 'lib/configs/env.js';

/*
 * Where the published URLs come from, and where they must not come from.
 *
 * A client fetches this document to learn where to send its users and its tokens. If a request header
 * could decide any of those URLs, an attacker who can add a header — a misconfigured proxy, an open
 * redirect in front of the server, a request they craft themselves — hands the next client a document
 * pointing wherever they like, and the client authenticates against it.
 *
 * The property holds today. What it had was nothing recording it: it lived in a comment inside
 * `test/configuration/secure.spec.ts`, which was deleted in the 041 refactor because its single case
 * named a framework this server does not use and was a skipped block around an empty body. Recorded
 * as G-004.
 *
 * Note while reading: the server DOES read forwarded headers, in `lib/plugins/rateLimit.ts`, to decide
 * which origin a request is counted against. That is a different use and this case does not constrain
 * it. What is constrained is URL CONSTRUCTION — stating it that way is what stops the case being
 * repaired by loosening it the next time somebody needs a header for something.
 */

const STEERED = {
	'x-forwarded-host': 'attacker.example.com',
	'x-forwarded-proto': 'https',
	'x-forwarded-port': '8443',
	forwarded: 'host=attacker.example.com;proto=https'
};

function urlsIn(document: Record<string, unknown>): string[] {
	return Object.entries(document)
		.filter(
			([key, value]) =>
				typeof value === 'string' &&
				(key.endsWith('_endpoint') || key.endsWith('_uri') || key === 'issuer')
		)
		.map(([, value]) => value as string);
}

/**
 * @proves The URLs a client is handed follow the issuer this server was configured with, and no
 * request header can steer them somewhere else.
 */
describe('the published endpoint URLs', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('follow the configured issuer when forwarded headers name another origin', async () => {
		const { data } = await agent['.well-known']['openid-configuration'].get({
			headers: STEERED
		});
		if (!data) throw new Error('expected a discovery document');

		const urls = urlsIn(data as Record<string, unknown>);

		expect(urls.length).toBeGreaterThan(0);
		expect(urls.filter((url) => !url.startsWith(ISSUER))).toEqual([]);
		expect(data).toHaveProperty('issuer', ISSUER);
	});

	it('follow the configured issuer in the OAuth metadata document too, under the same headers', async () => {
		const { data } = await agent['.well-known'][
			'oauth-authorization-server'
		].get({ headers: STEERED });
		if (!data)
			throw new Error('expected an authorization server metadata document');

		const urls = urlsIn(data as Record<string, unknown>);

		expect(urls.length).toBeGreaterThan(0);
		expect(urls.filter((url) => !url.startsWith(ISSUER))).toEqual([]);
		expect(data).toHaveProperty('issuer', ISSUER);
	});
});
