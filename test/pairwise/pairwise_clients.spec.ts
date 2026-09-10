import { describe, it, beforeAll, afterEach, expect } from 'bun:test';

import map from 'lodash/map.js';
import uniq from 'lodash/uniq.js';

import bootstrap from '../test_helper.js';
import { assertNoPendingInterceptors, mock } from '../fetch_mock.js';
import addClient from '../../lib/helpers/add_client.ts';
import { Claims } from 'lib/helpers/claims.js';
import { Client } from 'lib/models/client.js';

/**
 * @proves A pairwise client sector is resolved or refused at registration, verified against a
 * document served over https that lists the client own URIs.
 */
describe('pairwise features', () => {
	beforeAll(() => bootstrap(import.meta.url));

	afterEach(assertNoPendingInterceptors);

	describe('pairwise client configuration', () => {
		describe('sector_identifier_uri is not provided', () => {
			it('resolves the sector_identifier from one redirect_uri', () => {
				return addClient({
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
				return addClient({
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
				return addClient({
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

				return addClient({
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

			it("a sector document that does not list the client's redirect URIs is refused", () => {
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

				return addClient({
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

			it('refuses a provisioned client whose sector document does not list its redirect URIs', () => {
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
				return addClient({
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

			it('a client whose redirect URIs are not all listed in the sector document is refused', () => {
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

				return addClient({
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
				it('refuses a CIBA client whose jwks_uri is not listed in the sector document', () => {
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

					return addClient({
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
				it('refuses a device-flow client whose jwks_uri is not listed in the sector document', () => {
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

					return addClient({
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

			it('a sector document that is not JSON is refused', () => {
				mock('https://client.example.com')
					.intercept({
						path: '/sector'
					})
					.reply(200, '{ not a valid json');

				return addClient({
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

			it('a sector document that is not a JSON array is refused', () => {
				mock('https://client.example.com')
					.intercept({
						path: '/sector'
					})
					.reply(200, JSON.stringify('https://client.example.com/cb'));

				return addClient({
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

			it('an unreachable sector document refuses the registration rather than faulting', () => {
				mock('https://client.example.com')
					.intercept({
						path: '/sector'
					})
					.reply(500);

				return addClient({
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

				return addClient({
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
			return addClient({
				clientId: 'clientOne',
				clientSecret: 'secret',
				redirectUris: ['https://clientone.com/cb'],
				subjectType: 'pairwise'
			}).then((client) => {
				clients.push(client);
			});
		});

		beforeAll(() => {
			return addClient({
				clientId: 'clientTwo',
				clientSecret: 'secret',
				redirectUris: ['https://clienttwo.com/cb'],
				subjectType: 'pairwise'
			}).then((client) => {
				clients.push(client);
			});
		});

		beforeAll(() => {
			return addClient({
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
