import { describe, it, beforeAll } from 'bun:test';
import { expect } from 'chai';

import bootstrap, { agent } from '../test_helper.js';

const endpoint = () => agent['.well-known']['openid-configuration'].get();

// Keys that must always be present regardless of feature state.
const ALWAYS_PRESENT = [
	'issuer',
	'authorization_endpoint',
	'token_endpoint',
	'jwks_uri',
	'response_types_supported',
	'response_modes_supported',
	'subject_types_supported',
	'code_challenge_methods_supported',
	'id_token_signing_alg_values_supported',
	'token_endpoint_auth_methods_supported',
	'token_endpoint_auth_signing_alg_values_supported',
	'authorization_response_iss_parameter_supported',
	'scopes_supported',
	'grant_types_supported',
	'claims_supported'
];

// A representative feature-gated key per governing flag.
const FEATURE_GATED = [
	'pushed_authorization_request_endpoint',
	'dpop_signing_alg_values_supported',
	'introspection_endpoint',
	'claims_parameter_supported',
	'device_authorization_endpoint',
	'end_session_endpoint',
	'registration_endpoint',
	'revocation_endpoint',
	'backchannel_logout_supported',
	'tls_client_certificate_bound_access_tokens',
	'authorization_details_types_supported',
	'id_token_encryption_alg_values_supported',
	'request_parameter_supported',
	'userinfo_endpoint',
	'userinfo_signing_alg_values_supported',
	'userinfo_encryption_alg_values_supported',
	'authorization_signing_alg_values_supported',
	'introspection_signing_alg_values_supported',
	'backchannel_authentication_endpoint',
	'require_signed_request_object'
];

describe('discovery pruning', () => {
	describe('all features enabled', () => {
		beforeAll(async () => {
			await bootstrap(import.meta.url, { config: 'all_features' })();
		});

		it('includes every feature-gated key and all always-present keys', async () => {
			const { data } = await endpoint();
			expect(data).to.contain.keys([...ALWAYS_PRESENT, ...FEATURE_GATED]);
		});
	});

	describe('all optional features disabled', () => {
		beforeAll(async () => {
			await bootstrap(import.meta.url, { config: 'minimal' })();
		});

		it('drops every feature-gated key but keeps always-present keys', async () => {
			const { data } = await endpoint();
			expect(data).to.contain.keys(ALWAYS_PRESENT);
			for (const key of FEATURE_GATED) {
				expect(data).not.to.have.property(key);
			}
		});

		it('preserves the meaningful request_uri_parameter_supported: false', async () => {
			const { data } = await endpoint();
			expect(data).to.have.property('request_uri_parameter_supported', false);
		});
	});

	describe('multi-feature key gating', () => {
		beforeAll(async () => {
			await bootstrap(import.meta.url, { config: 'multi_feature' })();
		});

		it('drops a key when any of its required features is disabled', async () => {
			const { data } = await endpoint();
			// userinfo + jwtUserinfo on -> signing present; encryption off -> encryption absent.
			expect(data).to.have.property('userinfo_signing_alg_values_supported');
			expect(data).not.to.have.property(
				'userinfo_encryption_alg_values_supported'
			);
			expect(data).not.to.have.property(
				'userinfo_encryption_enc_values_supported'
			);
		});
	});
});
