import { strict as assert } from 'node:assert';
import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import addClient from '../../lib/helpers/add_client.ts';
import provider from 'lib/index.js';

describe('OAuth 2.0 for Native Apps Best Current Practice features', () => {
	let setup = null;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url)();
	});

	describe('changed native client validations', () => {
		describe('Private-use URI Scheme Redirection', () => {
			it('allows custom uri scheme uris with localhost', function () {
				return addClient(provider, {
					application_type: 'native',
					clientId: 'native-custom',
					grant_types: ['authorization_code'],
					response_types: ['code'],
					token_endpoint_auth_method: 'none',
					redirectUris: [
						'com.example.app://localhost/op/callback',
						'com.example.app:/op/callback'
					]
				});
			});

			it('rejects custom schemes without dots with reverse domain name scheme recommendation', function () {
				return assert.rejects(
					addClient(provider, {
						application_type: 'native',
						clientId: 'native-custom',
						grant_types: ['authorization_code'],
						response_types: ['code'],
						token_endpoint_auth_method: 'none',
						redirectUris: ['myapp:/op/callback']
					}),
					(err) => {
						expect(err).toHaveProperty('message', 'invalid_redirect_uri');
						expect(err).toHaveProperty(
							'error_description',
							'redirectUris for native clients using Custom URI scheme should use reverse domain name based scheme'
						);
						return true;
					}
				);
			});
		});

		describe('Claimed HTTPS URI Redirection', () => {
			it('allows claimed https uris', function () {
				return addClient(provider, {
					application_type: 'native',
					clientId: 'native-custom',
					grant_types: ['authorization_code'],
					response_types: ['code'],
					token_endpoint_auth_method: 'none',
					redirectUris: ['https://claimed.example.com/op/callback']
				});
			});

			it('rejects https if using loopback uris', function () {
				return assert.rejects(
					addClient(provider, {
						application_type: 'native',
						clientId: 'native-custom',
						grant_types: ['authorization_code'],
						response_types: ['code'],
						token_endpoint_auth_method: 'none',
						redirectUris: ['https://localhost/op/callback']
					}),
					(err) => {
						expect(err).toHaveProperty('message', 'invalid_redirect_uri');
						expect(err).toHaveProperty(
							'error_description',
							'redirectUris for native clients using claimed HTTPS URIs must not be using localhost as hostname'
						);
						return true;
					}
				);
			});
		});

		describe('Loopback Interface Redirection', () => {
			it('catches invalid urls being passed in', function () {
				return addClient(provider, {
					application_type: 'native',
					clientId: 'native-custom',
					grant_types: ['authorization_code'],
					response_types: ['code'],
					token_endpoint_auth_method: 'none',
					redirectUris: ['http://127.0.0.1:2355/op/callback']
				}).then((client) => {
					expect(client.redirectUriAllowed('http:')).toBeFalse();
					expect(client.redirectUriAllowed('http://127.0.0.')).toBeFalse();
					expect(client.redirectUriAllowed('http://127.0.0.1::')).toBeFalse();
				});
			});

			it('allows http protocol localhost loopback uris', function () {
				return addClient(provider, {
					application_type: 'native',
					clientId: 'native-custom',
					grant_types: ['authorization_code'],
					response_types: ['code'],
					token_endpoint_auth_method: 'none',
					redirectUris: ['http://localhost/op/callback']
				}).then((client) => {
					expect(client.redirectUris).toContain('http://localhost/op/callback');
					expect(
						client.redirectUriAllowed('http://localhost/op/callback')
					).toBeTrue();
				});
			});

			it('allows http protocol IPv4 loopback uris', function () {
				return addClient(provider, {
					application_type: 'native',
					clientId: 'native-custom',
					grant_types: ['authorization_code'],
					response_types: ['code'],
					token_endpoint_auth_method: 'none',
					redirectUris: ['http://127.0.0.1/op/callback']
				}).then((client) => {
					expect(client.redirectUris).toContain('http://127.0.0.1/op/callback');
					expect(
						client.redirectUriAllowed('http://127.0.0.1/op/callback')
					).toBeTrue();
				});
			});

			it('allows http protocol IPv6 loopback uris', function () {
				return addClient(provider, {
					application_type: 'native',
					clientId: 'native-custom',
					grant_types: ['authorization_code'],
					response_types: ['code'],
					token_endpoint_auth_method: 'none',
					redirectUris: ['http://[::1]/op/callback']
				}).then((client) => {
					expect(client.redirectUris).toContain('http://[::1]/op/callback');
					expect(
						client.redirectUriAllowed('http://[::1]/op/callback')
					).toBeTrue();
				});
			});

			it('rejects http protocol uris not using loopback uris', function () {
				return assert.rejects(
					addClient(provider, {
						application_type: 'native',
						clientId: 'native-custom',
						grant_types: ['authorization_code'],
						response_types: ['code'],
						token_endpoint_auth_method: 'none',
						redirectUris: ['http://rp.example.com/op/callback']
					}),
					(err) => {
						expect(err).toHaveProperty('message', 'invalid_redirect_uri');
						expect(err).toHaveProperty(
							'error_description',
							'redirectUris for native clients using http as a protocol can only use loopback addresses as hostnames'
						);
						return true;
					}
				);
			});
		});
	});
});
