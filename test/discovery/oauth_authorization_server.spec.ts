import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { ISSUER } from 'lib/configs/env.js';
import { ApplicationConfig } from 'lib/configs/application.js';

const oauthMetadata = agent['.well-known']['oauth-authorization-server'];
const oidcMetadata = agent['.well-known']['openid-configuration'];

/*
 * The fourteen members whose registering specification is OpenID Connect and whose subject matter no
 * OAuth-registered member this server emits refers to. Spelled out rather than derived from the
 * classification table: a test that reads the table would agree with the table by construction and
 * prove nothing about it.
 */
const OIDC_ONLY = [
	'userinfo_endpoint',
	'userinfo_signing_alg_values_supported',
	'userinfo_encryption_alg_values_supported',
	'userinfo_encryption_enc_values_supported',
	'id_token_signing_alg_values_supported',
	'id_token_encryption_alg_values_supported',
	'id_token_encryption_enc_values_supported',
	'subject_types_supported',
	'acr_values_supported',
	'claims_supported',
	'claims_parameter_supported',
	'end_session_endpoint',
	'backchannel_logout_supported',
	'backchannel_logout_session_supported'
];

// The OAuth extensions this server implements, each registered by an IETF OAuth RFC or admitted
// because an RFC 8414 member is unreadable without it (research D2).
const OAUTH_EXTENSIONS = [
	'pushed_authorization_request_endpoint',
	// `require_pushed_authorization_requests` is deliberately absent: its value comes from
	// ClientDefaults, defaults to false, and is not in MEANINGFUL_FALSE, so the falsy sweep removes it
	// from both documents. Its presence tracks the client default, not `par.enabled`.
	'dpop_signing_alg_values_supported',
	'device_authorization_endpoint',
	'tls_client_certificate_bound_access_tokens',
	'authorization_details_types_supported',
	'authorization_response_iss_parameter_supported',
	'introspection_signing_alg_values_supported',
	'require_signed_request_object',
	'request_parameter_supported',
	'request_object_signing_alg_values_supported',
	'backchannel_authentication_endpoint',
	'backchannel_token_delivery_modes_supported',
	'authorization_signing_alg_values_supported'
];

// RFC 8414 §2 marks these two REQUIRED; §3.3 requires the response be JSON. Everything else in the
// document is optional, which is why the minimal-configuration case below is worth its own suite:
// it is the only one that proves the pruning cannot strip the document below validity.
const RFC_8414_REQUIRED = ['issuer', 'response_types_supported'];

/**
 * @proves The RFC 8414 document carries the required members, locates its endpoints absolutely,
 * omits every OIDC-only member, and agrees with the OIDC document on the rest.
 */
describe('/.well-known/oauth-authorization-server', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('responds with json 200', async () => {
		const { status, response } = await oauthMetadata.get();

		expect(status).toBe(200);
		expect(response.headers.get('content-type')).toMatch(/application\/json/);
	});

	it('identifies the issuer exactly', async () => {
		const { data } = await oauthMetadata.get();
		if (!data) throw new Error('expected response data');

		expect(data.issuer).toBe(ISSUER);
	});

	it('carries the members RFC 8414 marks REQUIRED', async () => {
		const { data } = await oauthMetadata.get();
		if (!data) throw new Error('expected response data');

		for (const member of RFC_8414_REQUIRED) {
			expect(data).toHaveProperty(member);
		}
	});

	// The point of the feature: a client that has only the issuer URL can reach the endpoints without
	// parsing an OpenID Connect document. Absolute, and identical to what the OIDC document publishes.
	it('locates the endpoints, absolute and equal to the OIDC document', async () => {
		const { data } = await oauthMetadata.get();
		const { data: oidc } = await oidcMetadata.get();
		if (!data || !oidc) throw new Error('expected response data');

		for (const member of [
			'authorization_endpoint',
			'token_endpoint',
			'jwks_uri'
		] as const) {
			expect(data[member]).toBe(oidc[member]);
			expect(String(data[member]).startsWith(ISSUER)).toBe(true);
		}
	});

	it('is readable cross-origin by an unrelated origin', async () => {
		const origin = 'https://unrelated.example';
		const { response } = await oauthMetadata.get({
			headers: { origin }
		});

		expect(response.headers.get('access-control-allow-origin')).toBe(origin);
	});
});

describe('/.well-known/oauth-authorization-server at all features', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'all_features' });
	});

	it('omits every OIDC-only member', async () => {
		const { data } = await oauthMetadata.get();
		if (!data) throw new Error('expected response data');

		const leaked = OIDC_ONLY.filter((member) => member in data);

		expect(leaked).toEqual([]);
	});

	it('advertises the OAuth extensions the server implements', async () => {
		const { data } = await oauthMetadata.get();
		if (!data) throw new Error('expected response data');

		const missing = OAUTH_EXTENSIONS.filter((member) => !(member in data));

		expect(missing).toEqual([]);
	});

	// Flag-driven withdrawal, on the same fetch and with no restart: both documents are recomputed per
	// request from the live configuration.
	it.each([
		['par.enabled', 'pushed_authorization_request_endpoint'],
		['dpop.enabled', 'dpop_signing_alg_values_supported'],
		['introspection.enabled', 'introspection_endpoint'],
		['revocation.enabled', 'revocation_endpoint'],
		['registration.enabled', 'registration_endpoint'],
		['deviceFlow.enabled', 'device_authorization_endpoint'],
		['mTLS.enabled', 'tls_client_certificate_bound_access_tokens'],
		['ciba.enabled', 'backchannel_authentication_endpoint'],
		[
			'richAuthorizationRequests.enabled',
			'authorization_details_types_supported'
		],
		['requestObjects.enabled', 'require_signed_request_object'],
		['responseMode.jwt.enabled', 'authorization_signing_alg_values_supported'],
		['jwtIntrospection.enabled', 'introspection_signing_alg_values_supported']
	])('withdraws the members %s governs', async (flag, member) => {
		const config = ApplicationConfig as Record<string, unknown>;
		const original = config[flag];

		try {
			expect((await oauthMetadata.get()).data).toHaveProperty(member);

			config[flag] = false;
			const { data } = await oauthMetadata.get();
			if (!data) throw new Error('expected response data');

			expect(member in data).toBe(false);
		} finally {
			// ApplicationConfig is process-wide; leaving it flipped leaks into every later suite.
			config[flag] = original;
		}
	});

	/*
	 * The cheapest available proof that the audience filter runs BEFORE the feature-flag prune: these
	 * flags govern OIDC-only members exclusively, so by the time the prune runs there is nothing of
	 * theirs left to remove and this document cannot move.
	 */
	it.each([
		'userinfo.enabled',
		'jwtUserinfo.enabled',
		'rpInitiatedLogout.enabled',
		'backchannelLogout.enabled',
		'claimsParameter.enabled'
	])('is unmoved by %s, which governs only OIDC-only members', async (flag) => {
		const config = ApplicationConfig as Record<string, unknown>;
		const original = config[flag];

		try {
			const before = (await oauthMetadata.get()).data;

			config[flag] = false;
			const after = (await oauthMetadata.get()).data;

			expect(after).toEqual(before);
		} finally {
			config[flag] = original;
		}
	});

	it('agrees with the OIDC document on every shared member', async () => {
		const { data } = await oauthMetadata.get();
		const { data: oidc } = await oidcMetadata.get();
		if (!data || !oidc) throw new Error('expected response data');

		const oidcBody = oidc as Record<string, unknown>;
		const disagreeing = Object.keys(data).filter(
			(member) =>
				JSON.stringify(oidcBody[member]) !==
				JSON.stringify((data as Record<string, unknown>)[member])
		);

		expect(disagreeing).toEqual([]);
	});

	it('is a subset of the OIDC document', async () => {
		const { data } = await oauthMetadata.get();
		const { data: oidc } = await oidcMetadata.get();
		if (!data || !oidc) throw new Error('expected response data');

		const extra = Object.keys(data).filter((member) => !(member in oidc));

		expect(extra).toEqual([]);
	});

	/*
	 * `claim_types_supported` is registered by OIDC Discovery, yet it appears here — pinned rather than
	 * accidental. It is not produced by calculateDiscovery(); it ships as a default inside
	 * ApplicationConfig.discovery, so it arrives through the override stage, which runs after the
	 * audience filter and feeds both documents alike. The filter governs what the server computes; the
	 * override stage is the operator's, and RFC 8414 §2 permits the extra member. An operator who does
	 * not want it can set it to undefined.
	 */
	it('carries the shipped claim_types_supported default into both documents', async () => {
		const { data } = await oauthMetadata.get();
		if (!data) throw new Error('expected response data');

		expect(data).toHaveProperty('claim_types_supported');
	});

	// Operator overrides run last and fill only absent members, so they reach both documents equally.
	it('carries operator-supplied metadata into both documents', async () => {
		const original = { ...ApplicationConfig.discovery };
		ApplicationConfig.discovery.service_documentation =
			'https://docs.example.com';

		try {
			const { data } = await oauthMetadata.get();
			const { data: oidc } = await oidcMetadata.get();

			expect(data).toHaveProperty(
				'service_documentation',
				'https://docs.example.com'
			);
			expect(oidc).toHaveProperty(
				'service_documentation',
				'https://docs.example.com'
			);
		} finally {
			ApplicationConfig.discovery = original;
		}
	});
});

// Every optional capability off, including the two that default to on. RFC 8414 §2 still has to hold.
describe('/.well-known/oauth-authorization-server at minimal configuration', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'minimal' });
	});

	it('remains a valid RFC 8414 document', async () => {
		const { status, data } = await oauthMetadata.get();
		if (!data) throw new Error('expected response data');

		expect(status).toBe(200);
		for (const member of RFC_8414_REQUIRED) {
			expect(data).toHaveProperty(member);
		}
		expect(data.issuer).toBe(ISSUER);
	});
});
