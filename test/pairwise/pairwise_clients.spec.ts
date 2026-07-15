import { describe, it, beforeAll, afterEach, expect } from 'bun:test';

import map from 'lodash/map.js';
import uniq from 'lodash/uniq.js';

import bootstrap from '../test_helper.js';
import { assertNoPendingInterceptors, mock } from '../fetch_mock.js';
import addClient from '../../lib/helpers/add_client.ts';
import { Claims } from 'lib/helpers/claims.js';
import { provider } from 'lib/provider.js';
import { Client } from 'lib/models/client.js';

describe('pairwise features', () => {
	beforeAll(() => bootstrap(import.meta.url));

	afterEach(assertNoPendingInterceptors);

	describe('pairwise client configuration', () => {
		describe('sector_identifier_uri is not provided', () => {
			it('resolves the sector_identifier from one redirect_uri', () => {
				return addClient(provider, {
					clientId: 'client',
					clientSecret: 'secret',
					redirectUris: ['https://client.example.com/cb'],
					subjectType: 'pairwise'
				}).then((client) => {
					expect(client.sectorIdentifier).toBeTruthy();
					expect(client.sectorIdentifier).toBe('client.example.com');
				});
			});

			it('resolves the sector_identifier if redirect_uris hosts are the same', () => {
				return addClient(provider, {
					clientId: 'client',
					clientSecret: 'secret',
					redirectUris: [
						'https://client.example.com/cb',
						'https://client.example.com/forum/cb'
					],
					subjectType: 'pairwise'
				}).then((client) => {
					expect(client.sectorIdentifier).toBeTruthy();
					expect(client.sectorIdentifier).toBe('client.example.com');
				});
			});

			it('fails to validate when multiple redirect_uris hosts are provided', () => {
				return addClient(provider, {
					clientId: 'client',
					clientSecret: 'secret',
					redirectUris: [
						'https://client.example.com/cb',
						'https://wrongsubdomain.example.com/forum/cb'
					],
					subjectType: 'pairwise'
				}).then(
					(client) => {
						expect(client).toBeFalsy();
					},
					(err) => {
						expect(err).toBeTruthy();
						expect(err.message).toBe('invalid_client_metadata');
						expect(err.error_description).toBe(
							'sector_identifier_uri is mandatory property'
						);
					}
				);
			});
		});

		describe('sector_identifier_uri is provided', () => {
			it('is not ignored even without subjectType=pairwise', () => {
				mock('https://foobar.example.com')
					.intercept({
						path: '/sector'
					})
					.reply(
						200,
						JSON.stringify([
							'https://client.example.com/cb',
							'https://another.example.com/forum/cb'
						])
					);

				return addClient(provider, {
					clientId: 'client',
					clientSecret: 'secret',
					redirectUris: [
						'https://client.example.com/cb',
						'https://another.example.com/forum/cb'
					],
					sector_identifier_uri: 'https://foobar.example.com/sector',
					subjectType: 'public'
				}).then((client) => {
					expect(client).toBeTruthy();
					expect(client.sectorIdentifier).toBe('foobar.example.com');
				});
			});

			it('validates the sector from the provided uri', () => {
				mock('https://foobar.example.com')
					.intercept({
						path: '/sector'
					})
					.reply(
						200,
						JSON.stringify([
							'https://client.example.com/cb',
							'https://another.example.com/forum/cb'
						])
					);

				return addClient(provider, {
					clientId: 'client',
					clientSecret: 'secret',
					redirectUris: [
						'https://client.example.com/cb',
						'https://another.example.com/forum/cb'
					],
					sector_identifier_uri: 'https://foobar.example.com/sector',
					subjectType: 'pairwise'
				}).then((client) => {
					expect(client).toBeTruthy();
					expect(client.sectorIdentifier).toBe('foobar.example.com');
				});
			});

			it('validates the sector from the provided uri for static clients too', () => {
				mock('https://foobar.example.com')
					.intercept({
						path: '/sector'
					})
					.reply(
						200,
						JSON.stringify([
							'https://client.example.com/cb',
							'https://another.example.com/forum/cb'
						])
					);

				return Client.find('client-static-with-sector').then((client) => {
					expect(client).toBeTruthy();
					expect(client.sectorIdentifier).toBe('foobar.example.com');
				});
			});

			it('must be an https uri', () => {
				return addClient(provider, {
					clientId: 'client',
					clientSecret: 'secret',
					redirectUris: [
						'https://client.example.com/cb',
						'https://another.example.com/forum/cb'
					],
					sector_identifier_uri: 'http://client.example.com/sector',
					subjectType: 'pairwise'
				}).then(
					(client) => {
						expect(client).toBeFalsy();
					},
					(err) => {
						expect(err.message).toBe('invalid_client_metadata');
						// The https-uri shape check moved to the TypeBox ClientSchema, which
						// reports a generic error_description and the specifics in error_detail.
						expect(err.error_description).toBe(
							'client metadata validation error'
						);
						expect(err.error_detail).toContain(
							"/sectorIdentifierUri Expected string to match 'https-uri' format"
						);
					}
				);
			});

			it('validates all redirect_uris are in the uri', () => {
				mock('https://client.example.com')
					.intercept({
						path: '/sector'
					})
					.reply(
						200,
						JSON.stringify([
							'https://client.example.com/cb',
							'https://another.example.com/forum/cb'
						])
					);

				return addClient(provider, {
					clientId: 'client',
					clientSecret: 'secret',
					redirectUris: [
						'https://client.example.com/cb',
						'https://missing.example.com/forum/cb'
					],
					sector_identifier_uri: 'https://client.example.com/sector',
					subjectType: 'pairwise'
				}).then(
					(client) => {
						expect(client).toBeFalsy();
					},
					(err) => {
						expect(err).toBeTruthy();
						expect(err.message).toBe('invalid_client_metadata');
						expect(err.error_description).toBe(
							'all registered redirectUris must be included in the sector_identifier_uri response'
						);
					}
				);
			});

			describe('features.ciba', () => {
				it('validates jwks_uri is in the response', () => {
					mock('https://client.example.com')
						.intercept({
							path: '/sector'
						})
						.reply(
							200,
							JSON.stringify([
								'https://client.example.com/cb',
								'https://another.example.com/forum/cb'
							])
						);

					return addClient(provider, {
						clientId: 'client',
						responseTypes: [],
						backchannel_token_delivery_mode: 'poll',
						grantTypes: ['urn:openid:params:grant-type:ciba'],
						token_endpoint_auth_method: 'private_key_jwt',
						jwks_uri: 'https://client.example.com/jwks',
						sector_identifier_uri: 'https://client.example.com/sector',
						subjectType: 'pairwise'
					}).then(
						(client) => {
							expect(client).toBeFalsy();
						},
						(err) => {
							expect(err).toBeTruthy();
							expect(err.message).toBe('invalid_client_metadata');
							expect(err.error_description).toBe(
								"client's jwks_uri must be included in the sector_identifier_uri response"
							);
						}
					);
				});
			});

			describe('features.deviceFlow', () => {
				it('validates jwks_uri is in the response', () => {
					mock('https://client.example.com')
						.intercept({
							path: '/sector'
						})
						.reply(
							200,
							JSON.stringify([
								'https://client.example.com/cb',
								'https://another.example.com/forum/cb'
							])
						);

					return addClient(provider, {
						clientId: 'client',
						responseTypes: [],
						grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
						token_endpoint_auth_method: 'private_key_jwt',
						jwks_uri: 'https://client.example.com/jwks',
						sector_identifier_uri: 'https://client.example.com/sector',
						subjectType: 'pairwise'
					}).then(
						(client) => {
							expect(client).toBeFalsy();
						},
						(err) => {
							expect(err).toBeTruthy();
							expect(err.message).toBe('invalid_client_metadata');
							expect(err.error_description).toBe(
								"client's jwks_uri must be included in the sector_identifier_uri response"
							);
						}
					);
				});
			});

			it('validates the response is a json', () => {
				mock('https://client.example.com')
					.intercept({
						path: '/sector'
					})
					.reply(200, '{ not a valid json');

				return addClient(provider, {
					clientId: 'client',
					clientSecret: 'secret',
					redirectUris: [
						'https://client.example.com/cb',
						'https://missing.example.com/forum/cb'
					],
					sector_identifier_uri: 'https://client.example.com/sector',
					subjectType: 'pairwise'
				}).then(
					(client) => {
						expect(client).toBeFalsy();
					},
					(err) => {
						expect(err).toBeTruthy();
						expect(err.message).toBe('invalid_client_metadata');
						expect(err.error_description).toBe(
							'failed to parse sector_identifier_uri JSON response'
						);
					}
				);
			});

			it('validates only accepts json array responses', () => {
				mock('https://client.example.com')
					.intercept({
						path: '/sector'
					})
					.reply(200, JSON.stringify('https://client.example.com/cb'));

				return addClient(provider, {
					clientId: 'client',
					clientSecret: 'secret',
					redirectUris: [
						'https://client.example.com/cb',
						'https://missing.example.com/forum/cb'
					],
					sector_identifier_uri: 'https://client.example.com/sector',
					subjectType: 'pairwise'
				}).then(
					(client) => {
						expect(client).toBeFalsy();
					},
					(err) => {
						expect(err).toBeTruthy();
						expect(err.message).toBe('invalid_client_metadata');
						expect(err.error_description).toBe(
							'sector_identifier_uri must return single JSON array'
						);
					}
				);
			});

			it('handles got lib errors', () => {
				mock('https://client.example.com')
					.intercept({
						path: '/sector'
					})
					.reply(500);

				return addClient(provider, {
					clientId: 'client',
					clientSecret: 'secret',
					redirectUris: [
						'https://client.example.com/cb',
						'https://missing.example.com/forum/cb'
					],
					sector_identifier_uri: 'https://client.example.com/sector',
					subjectType: 'pairwise'
				}).then(
					(client) => {
						expect(client).toBeFalsy();
					},
					(err) => {
						expect(err).toBeTruthy();
						expect(err.message).toBe('invalid_client_metadata');
						expect(err.error_description).toBe(
							'unexpected sector_identifier_uri response status code, expected 200 OK, got 500 Internal Server Error'
						);
					}
				);
			});

			it('doesnt accepts 200s, rejects even on redirect', () => {
				mock('https://client.example.com')
					.intercept({
						path: '/sector'
					})
					.reply(201, JSON.stringify('https://client.example.com/cb'));

				return addClient(provider, {
					clientId: 'client',
					clientSecret: 'secret',
					redirectUris: [
						'https://client.example.com/cb',
						'https://missing.example.com/forum/cb'
					],
					sector_identifier_uri: 'https://client.example.com/sector',
					subjectType: 'pairwise'
				}).then(
					(client) => {
						expect(client).toBeFalsy();
					},
					(err) => {
						expect(err).toBeTruthy();
						expect(err.message).toBe('invalid_client_metadata');
						expect(err.error_description).toBe(
							'unexpected sector_identifier_uri response status code, expected 200 OK, got 201 Created'
						);
					}
				);
			});
		});
	});

	describe('pairwise client Subject calls', () => {
		const clients = [];

		beforeAll(() => {
			return addClient(provider, {
				clientId: 'clientOne',
				clientSecret: 'secret',
				redirectUris: ['https://clientone.com/cb'],
				subjectType: 'pairwise'
			}).then((client) => {
				clients.push(client);
			});
		});

		beforeAll(() => {
			return addClient(provider, {
				clientId: 'clientTwo',
				clientSecret: 'secret',
				redirectUris: ['https://clienttwo.com/cb'],
				subjectType: 'pairwise'
			}).then((client) => {
				clients.push(client);
			});
		});

		beforeAll(() => {
			return addClient(provider, {
				clientId: 'clientThree',
				clientSecret: 'secret',
				redirectUris: ['https://clientthree.com/cb']
			}).then((client) => {
				clients.push(client);
			});
		});

		it('returns different subs', async () => {
			const subs = await Promise.all(
				map(clients, async (client) => {
					const claims = new Claims(client, { sub: 'accountId' });
					claims.scope('openid');

					const { sub } = await claims.result();
					return sub;
				})
			);

			expect(subs).toHaveLength(3);
			expect(uniq(subs)).toHaveLength(3);
			expect(subs).toContain('accountId');
		});
	});
});
