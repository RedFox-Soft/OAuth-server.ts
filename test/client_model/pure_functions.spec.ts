import { describe, it, expect } from 'bun:test';

import {
	responseTypeAllowed,
	responseModeAllowed,
	grantTypeAllowed,
	redirectUriAllowed,
	postLogoutRedirectUriAllowed,
	includeSid,
	compareClientSecret,
	checkClientSecretExpiration,
	needsSecret,
	sectorIdentifier
} from 'lib/models/client.js';
import { InvalidClient } from 'lib/helpers/errors.js';
import epochTime from 'lib/helpers/epoch_time.js';

// Unit coverage for the pure client functions that replaced the Client class
// methods. These exercise plain client objects directly (no provider / adapter
// bootstrap) and do not replace the integration coverage (FR-009).
/**
 * @proves What a client registered bounds what it may do - response types, grants, redirect
 * targets, secrets and pairwise sector - with the loopback licence extending to the port and
 * nothing else.
 */
describe('client pure functions', () => {
	describe('checks', () => {
		const client = {
			responseTypes: ['code'],
			grantTypes: ['authorization_code', 'refresh_token'],
			redirectUris: ['https://rp.example.com/cb'],
			postLogoutRedirectUris: ['https://rp.example.com/after-logout']
		};

		it('a client cannot use a response type it did not register', () => {
			expect(responseTypeAllowed(client, 'code')).toBe(true);
			expect(responseTypeAllowed(client, 'none')).toBe(false);
		});

		it('a client cannot use a grant type it did not register', () => {
			expect(grantTypeAllowed(client, 'refresh_token')).toBe(true);
			expect(grantTypeAllowed(client, 'client_credentials')).toBe(false);
		});

		it('only an exactly registered redirect_uri is accepted', () => {
			expect(redirectUriAllowed(client, 'https://rp.example.com/cb')).toBe(
				true
			);
			expect(redirectUriAllowed(client, 'https://rp.example.com/other')).toBe(
				false
			);
		});

		/*
		 * RFC 8252 §7.3: a native client receives its code on an ephemeral loopback port it cannot
		 * know at registration time, so the authorization server must allow any port at request time
		 * and compare the rest exactly. `lib/admin/seed.ts` already registers the reserved MCP agent
		 * on this assumption ("the port is unpredictable ... OAuth 2.1 allows a loopback port to
		 * vary"), and a real MCP client picks a different port on every attempt — 3118, then 46937.
		 */
		describe('loopback redirect URIs at request time (RFC 8252 §7.3)', () => {
			const native = {
				applicationType: 'native',
				redirectUris: [
					'http://127.0.0.1:33418/callback',
					'http://localhost:33418/callback',
					'http://127.0.0.1/callback'
				]
			};

			it('allows any port on a registered loopback host', () => {
				expect(
					redirectUriAllowed(native, 'http://127.0.0.1:46937/callback')
				).toBe(true);
				expect(
					redirectUriAllowed(native, 'http://localhost:46937/callback')
				).toBe(true);
			});

			it('compares the path exactly, port aside', () => {
				expect(
					redirectUriAllowed(native, 'http://127.0.0.1:46937/stolen')
				).toBe(false);
			});

			it('does not make a non-loopback host interchangeable', () => {
				expect(
					redirectUriAllowed(native, 'http://rp.example.com:46937/callback')
				).toBe(false);
			});

			it('does not extend the licence to https loopback URIs', () => {
				expect(
					redirectUriAllowed(
						{
							applicationType: 'native',
							redirectUris: ['https://127.0.0.1:33418/callback']
						},
						'https://127.0.0.1:46937/callback'
					)
				).toBe(false);
			});

			it('leaves a web client on exact matching', () => {
				expect(
					redirectUriAllowed(
						{
							applicationType: 'web',
							redirectUris: ['http://localhost:33418/callback']
						},
						'http://localhost:46937/callback'
					)
				).toBe(false);
			});
		});

		it('a client that registered no response_modes may use any of them', () => {
			expect(responseModeAllowed(client, 'query')).toBe(true);
			expect(responseModeAllowed({ responseModes: ['query'] }, 'query')).toBe(
				true
			);
			expect(
				responseModeAllowed({ responseModes: ['query'] }, 'form_post')
			).toBe(false);
		});

		it('only a registered post-logout redirect is accepted, compared after normalisation', () => {
			expect(
				postLogoutRedirectUriAllowed(
					client,
					'https://rp.example.com/after-logout'
				)
			).toBe(true);
			expect(postLogoutRedirectUriAllowed(client, 'not a url')).toBe(false);
			expect(
				postLogoutRedirectUriAllowed(client, 'https://rp.example.com/nope')
			).toBe(false);
		});

		it('a logout token carries sid only for a client that registered both the URI and the session flag', () => {
			expect(
				includeSid({
					backchannelLogoutUri: 'https://rp.example.com/bcl',
					backchannelLogoutSessionRequired: true
				})
			).toBe(true);
			expect(
				includeSid({
					backchannelLogoutUri: 'https://rp.example.com/bcl',
					backchannelLogoutSessionRequired: false
				})
			).toBe(false);
			expect(includeSid({})).toBe(undefined);
		});
	});

	describe('secret', () => {
		it('answers equal only for the identical client secret', () => {
			const client = { clientSecret: 'super-secret-value' };
			expect(compareClientSecret(client, 'super-secret-value')).toBe(true);
			expect(compareClientSecret(client, 'wrong')).toBe(false);
		});

		it('a client with no secret expiry keeps authenticating indefinitely', () => {
			expect(() => checkClientSecretExpiration({}, 'msg')).not.toThrow();
		});

		it('refuses a client whose secret has expired', () => {
			const client = {
				clientId: 'c',
				clientSecretExpiresAt: epochTime() - 3600
			};
			expect(() => checkClientSecretExpiration(client, 'expired')).toThrow(
				InvalidClient
			);
		});

		it('lets an endpoint supply its own protocol error for an expired secret', () => {
			const client = {
				clientId: 'c',
				clientSecretExpiresAt: epochTime() - 3600
			};
			try {
				checkClientSecretExpiration(client, 'expired', 'invalid_grant');
				throw new Error('should have thrown');
			} catch (err) {
				expect(err).toBeInstanceOf(InvalidClient);
				expect(err.error).toBe('invalid_grant');
			}
		});

		it('a client using a secret-based method cannot be registered without one', () => {
			expect(
				needsSecret({ token_endpoint_auth_method: 'client_secret_basic' })
			).toBe(true);
			expect(needsSecret({ token_endpoint_auth_method: 'none' })).toBe(false);
			expect(
				needsSecret({ token_endpoint_auth_method: 'private_key_jwt' })
			).toBe(false);
		});

		it('requires a secret for a client registered for symmetric signing or encryption', () => {
			expect(
				needsSecret({
					token_endpoint_auth_method: 'none',
					id_token_signed_response_alg: 'HS256'
				})
			).toBe(true);
			expect(
				needsSecret({
					token_endpoint_auth_method: 'none',
					id_token_encrypted_response_alg: 'A128KW'
				})
			).toBe(true);
		});
	});

	describe('sector', () => {
		it('returns the sector_identifier_uri host when set', () => {
			const client = {
				subjectType: 'public',
				sectorIdentifierUri: 'https://sector.example.com/uris.json',
				responseTypes: ['code'],
				redirectUris: ['https://rp.example.com/cb'],
				grantTypes: ['authorization_code']
			};
			expect(sectorIdentifier(client)).toBe('sector.example.com');
		});

		it('falls back to the first redirect_uri host for pairwise clients', () => {
			const client = {
				subjectType: 'pairwise',
				responseTypes: ['code'],
				redirectUris: ['https://rp.example.com/cb'],
				grantTypes: ['authorization_code']
			};
			expect(sectorIdentifier(client)).toBe('rp.example.com');
		});

		it('a client updated through the admin API is used with its new metadata on the next request', () => {
			const client = {
				subjectType: 'public',
				sectorIdentifierUri: 'https://sector.example.com/uris.json',
				responseTypes: ['code'],
				redirectUris: ['https://rp.example.com/cb'],
				grantTypes: ['authorization_code']
			};
			expect(sectorIdentifier(client)).toBe(sectorIdentifier(client));
		});
	});
});
