import { afterAll, afterEach, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { ApplicationConfig } from '../../lib/configs/application.js';
import { present } from '../shape.js';

const DOCUMENTS = [
	'openid-configuration',
	'oauth-authorization-server'
] as const;
const CLIENT_AUTH_METHODS = [...ApplicationConfig.clientAuthMethods];

async function fetchDocument(
	name: (typeof DOCUMENTS)[number] = 'openid-configuration'
): Promise<Record<string, unknown>> {
	const { data } = await agent['.well-known'][name].get();
	return present(data, `the ${name} document`) as Record<string, unknown>;
}

function setEndpoints(introspection: boolean, revocation: boolean) {
	ApplicationConfig['introspection.enabled'] = introspection;
	ApplicationConfig['revocation.enabled'] = revocation;
}

function restore() {
	setEndpoints(false, false);
	ApplicationConfig.clientAuthMethods = [...CLIENT_AUTH_METHODS];
	ApplicationConfig['mTLS.enabled'] = false;
	ApplicationConfig['mTLS.tlsClientAuth'] = false;
}

/**
 * @proves A client reading either metadata document learns how to authenticate to introspection
 * and to revocation while each is served, and is told nothing about an endpoint that is not.
 */
describe('the introspection and revocation authentication metadata', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	afterAll(restore);
	afterEach(restore);

	for (const introspection of [false, true]) {
		for (const revocation of [false, true]) {
			for (const name of DOCUMENTS) {
				it(`names exactly the enabled endpoints' methods in ${name}, with introspection=${introspection} and revocation=${revocation}`, async () => {
					setEndpoints(introspection, revocation);
					const document = await fetchDocument(name);

					expect({
						introspection:
							'introspection_endpoint_auth_methods_supported' in document,
						revocation: 'revocation_endpoint_auth_methods_supported' in document
					}).toEqual({ introspection, revocation });
				});
			}
		}
	}

	it('names the assertion signing algorithms while a signed-assertion method is accepted', async () => {
		setEndpoints(true, true);
		const document = await fetchDocument();

		expect(
			document.introspection_endpoint_auth_signing_alg_values_supported
		).toEqual(document.token_endpoint_auth_signing_alg_values_supported);
		expect(
			document.revocation_endpoint_auth_signing_alg_values_supported
		).toEqual(document.token_endpoint_auth_signing_alg_values_supported);
	});

	it('names no assertion signing algorithms when no signed-assertion method is accepted', async () => {
		setEndpoints(true, true);
		ApplicationConfig.clientAuthMethods = ['client_secret_basic', 'none'];
		const document = await fetchDocument();

		expect(document).not.toHaveProperty(
			'introspection_endpoint_auth_signing_alg_values_supported'
		);
		expect(document).not.toHaveProperty(
			'revocation_endpoint_auth_signing_alg_values_supported'
		);
	});

	it('follows a change to the accepted methods without a restart', async () => {
		setEndpoints(true, true);
		ApplicationConfig.clientAuthMethods = CLIENT_AUTH_METHODS.filter(
			(method) => method !== 'client_secret_post'
		);
		const document = await fetchDocument();

		expect(
			document.introspection_endpoint_auth_methods_supported
		).not.toContain('client_secret_post');
		expect(document.introspection_endpoint_auth_methods_supported).toEqual(
			document.token_endpoint_auth_methods_supported
		);
		expect(document.revocation_endpoint_auth_methods_supported).toEqual(
			document.token_endpoint_auth_methods_supported
		);
	});

	it('follows enabling mutual-TLS client authentication without a restart', async () => {
		setEndpoints(true, true);
		ApplicationConfig['mTLS.enabled'] = true;
		ApplicationConfig['mTLS.tlsClientAuth'] = true;
		const document = await fetchDocument();

		expect(document.introspection_endpoint_auth_methods_supported).toContain(
			'tls_client_auth'
		);
		expect(document.revocation_endpoint_auth_methods_supported).toContain(
			'tls_client_auth'
		);
	});
});
