import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';

/*
 * What a default deployment advertises.
 *
 * This replaced a byte-for-byte comparison against a JSON fixture captured before a refactor that
 * has since shipped. The refactor is done, and a whole-document snapshot fails on every legitimate
 * addition with the repair being to re-record the fixture - which is the shape that trains people
 * to update a file rather than think about what changed.
 *
 * The claim worth keeping is narrower and outlives the refactor: an integrator pointing at a
 * deployment that has configured nothing sees exactly these capabilities. Naming the members means
 * a failure says which one appeared or vanished, and adding one is a deliberate act rather than a
 * fixture refresh. Values are asserted only where a client depends on the value rather than on the
 * member being present; the rest are covered directly in oauth_authorization_server.spec.ts,
 * discovery_pruning.spec.ts and metadata_classification.spec.ts.
 */
const DEFAULT_MEMBERS = [
	'authorization_endpoint',
	'authorization_response_iss_parameter_supported',
	'claim_types_supported',
	'claims_supported',
	'code_challenge_methods_supported',
	'end_session_endpoint',
	'grant_types_supported',
	'id_token_signing_alg_values_supported',
	'issuer',
	'jwks_uri',
	'request_uri_parameter_supported',
	'response_modes_supported',
	'response_types_supported',
	'scopes_supported',
	'subject_types_supported',
	'token_endpoint',
	'token_endpoint_auth_methods_supported',
	'token_endpoint_auth_signing_alg_values_supported',
	'userinfo_endpoint'
] as const;

/**
 * @proves A deployment that has configured nothing advertises exactly the default capability
 * set, rooted at the issuer it names.
 */
describe('the discovery document of a deployment that has configured nothing', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'discovery_parity' });
	});

	it('advertises exactly the default capability set, and no others', async () => {
		const { data } = await agent['.well-known']['openid-configuration'].get();

		expect(Object.keys(data as object).sort()).toEqual(
			[...DEFAULT_MEMBERS].sort()
		);
	});

	it('roots every advertised endpoint at the issuer it names', async () => {
		const doc = (await agent['.well-known']['openid-configuration'].get())
			.data as Record<string, string>;

		// A relative endpoint is unusable, and one rooted somewhere other than the issuer sends a
		// client to a server the issuer did not vouch for.
		const endpoints = DEFAULT_MEMBERS.filter((m) => m.endsWith('_endpoint'));
		expect(endpoints.length).toBeGreaterThan(0);

		for (const member of endpoints) {
			expect(doc[member], member).toStartWith(`${doc.issuer}/`);
		}
		expect(doc.jwks_uri).toStartWith(`${doc.issuer}/`);
	});

	it('offers PKCE with S256, which OAuth 2.1 requires of every client', async () => {
		const doc = (await agent['.well-known']['openid-configuration'].get())
			.data as Record<string, string[]>;

		// Advertised by default rather than only when something is switched on: a client that cannot
		// see S256 here has no way to know PKCE is mandatory.
		expect(doc.code_challenge_methods_supported).toContain('S256');
	});
});
