import { strict as assert } from 'node:assert';
import * as url from 'node:url';

import { expect, mock, spyOn } from 'bun:test';

import bootstrap from '../test_helper.js';
import provider, { errors } from '../../lib/index.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { InitialAccessToken } from 'lib/models/initial_access_token.js';
import { RegistrationAccessToken } from 'lib/models/registration_access_token.js';
import { TestAdapter } from 'test/models.js';

describe('client registration policies', () => {
	before(bootstrap(import.meta.url));
	beforeEach(() => mock.restore());

	describe('configuration', () => {
		it('must only be enabled in conjuction with adapter-backed initial access tokens', () => {
			expect(() => {
				provider.init({
					features: {
						registration: {
							enabled: true,
							policies: { foo() {} }
						}
					}
				});
			}).toThrow(
				'registration policies are only available in conjuction with adapter-backed initial access tokens'
			);
		});
	});

	describe('Registration & InitialAccessToken', () => {
		it('allows policies to run to be stored on an InitialAccessToken', async function () {
			const spy = mock();
			provider.once('initial_access_token.saved', spy);
			const value = await new InitialAccessToken({
				policies: ['empty-policy']
			}).save();

			expect(spy).toHaveBeenCalled();
			expect(spy.mock.calls[0][0]).toHaveProperty('policies', ['empty-policy']);

			expect(await InitialAccessToken.find(value)).toHaveProperty(
				'policies',
				['empty-policy']
			);
		});

		it('runs the policies when a client is getting created', async function () {
			const spy = spyOn(
				ApplicationConfig['registration.policies'],
				'empty-policy'
			);
			const value = await new InitialAccessToken({
				policies: ['empty-policy']
			}).save();

			await this.agent
				.post('/reg')
				.auth(value, { type: 'bearer' })
				.send({ redirect_uris: ['https://rp.example.com/cb'] })
				.expect(201);

			expect(spy).toHaveBeenCalledTimes(1);
		});

		it('allows for policies to set property defaults', async function () {
			ApplicationConfig['registration.policies']['set-default'] = (
				ctx,
				properties
			) => {
				if (!('id_token_signed_response_alg' in properties)) {
					properties.id_token_signed_response_alg = 'HS256';
				}
			};

			const value = await new InitialAccessToken({
				policies: ['set-default']
			}).save();

			await this.agent
				.post('/reg')
				.auth(value, { type: 'bearer' })
				.send({ redirect_uris: ['https://rp.example.com/cb'] })
				.expect(201)
				.expect(({ body }) => {
					expect(body).toHaveProperty('id_token_signed_response_alg', 'HS256');
				});

			await this.agent
				.post('/reg')
				.auth(value, { type: 'bearer' })
				.send({
					redirect_uris: ['https://rp.example.com/cb'],
					id_token_signed_response_alg: 'PS256'
				})
				.expect(201)
				.expect(({ body }) => {
					expect(body).toHaveProperty('id_token_signed_response_alg', 'PS256');
				});
		});

		it('allows for policies to force property values', async function () {
			ApplicationConfig['registration.policies']['force-default'] = (
				ctx,
				properties
			) => {
				properties.id_token_signed_response_alg = 'HS256';
			};

			const value = await new InitialAccessToken({
				policies: ['force-default']
			}).save();

			await this.agent
				.post('/reg')
				.auth(value, { type: 'bearer' })
				.send({
					redirect_uris: ['https://rp.example.com/cb'],
					id_token_signed_response_alg: 'PS256'
				})
				.expect(201)
				.expect(({ body }) => {
					expect(body).toHaveProperty('id_token_signed_response_alg', 'HS256');
				});
		});

		it('allows for policies to validate property values', async function () {
			ApplicationConfig['registration.policies']['throw-error'] = () => {
				throw new errors.InvalidClientMetadata('foo');
			};

			const value = await new InitialAccessToken({
				policies: ['throw-error']
			}).save();

			await this.agent
				.post('/reg')
				.auth(value, { type: 'bearer' })
				.send({
					redirect_uris: ['https://rp.example.com/cb'],
					id_token_signed_response_alg: 'PS256'
				})
				.expect(400)
				.expect(({ body }) => {
					expect(body).toHaveProperty('error', 'invalid_client_metadata');
					expect(body).toHaveProperty('error_description', 'foo');
				});
		});

		it('pushes the policy down to the registration access token', async function () {
			const value = await new InitialAccessToken({
				policies: ['empty-policy']
			}).save();

			const spy = mock();
			provider.once('registration_access_token.saved', spy);

			await this.agent
				.post('/reg')
				.auth(value, { type: 'bearer' })
				.send({ redirect_uris: ['https://rp.example.com/cb'] })
				.expect(201);

			expect(spy).toHaveBeenCalledTimes(1);
			expect(spy.mock.calls[0][0]).toHaveProperty('policies', ['empty-policy']);
		});

		it('can be done to push different policies to rat', async function () {
			ApplicationConfig['registration.policies']['change-rat-policy'] = async (
				ctx
			) => {
				ctx.oidc.entities.RegistrationAccessToken.policies = ['empty-policy'];
			};

			const value = await new InitialAccessToken({
				policies: ['change-rat-policy']
			}).save();

			const spy = mock();
			provider.once('registration_access_token.saved', spy);

			await this.agent
				.post('/reg')
				.auth(value, { type: 'bearer' })
				.send({ redirect_uris: ['https://rp.example.com/cb'] })
				.expect(201);

			expect(spy).toHaveBeenCalledTimes(1);
			expect(spy.mock.calls[0][0]).toHaveProperty('policies', ['empty-policy']);
		});

		it('policies must be an array', async function () {
			await assert.rejects(
				new InitialAccessToken({ policies: null }).save(),
				(err) => {
					expect(err).toHaveProperty('message', 'policies must be an array');
					return true;
				}
			);
			const saved = await new InitialAccessToken({
				policies: undefined
			}).save();
			TestAdapter.for('InitialAccessToken').syncUpdate(
				this.getTokenJti(saved),
				{
					policies: null
				}
			);

			return assert.rejects(InitialAccessToken.find(saved), (err) => {
				expect(err).toHaveProperty('message', 'policies must be an array');
				return true;
			});
		});

		it('policies array must have members', async function () {
			await assert.rejects(
				new InitialAccessToken({ policies: [] }).save(),
				(err) => {
					expect(err).toHaveProperty('message', 'policies must not be empty');
					return true;
				}
			);
			const saved = await new InitialAccessToken({
				policies: undefined
			}).save();
			TestAdapter.for('InitialAccessToken').syncUpdate(
				this.getTokenJti(saved),
				{
					policies: []
				}
			);

			return assert.rejects(InitialAccessToken.find(saved), (err) => {
				expect(err).toHaveProperty('message', 'policies must not be empty');
				return true;
			});
		});

		it('policies members must be strings', async function () {
			await assert.rejects(
				new InitialAccessToken({ policies: [null] }).save(),
				(err) => {
					expect(err).toHaveProperty('message', 'policies must be strings');
					return true;
				}
			);
			const saved = await new InitialAccessToken({
				policies: undefined
			}).save();
			TestAdapter.for('InitialAccessToken').syncUpdate(
				this.getTokenJti(saved),
				{
					policies: [null]
				}
			);

			return assert.rejects(InitialAccessToken.find(saved), (err) => {
				expect(err).toHaveProperty('message', 'policies must be strings');
				return true;
			});
		});

		it('policies members must be present in the provider configuration', async function () {
			await assert.rejects(
				new InitialAccessToken({ policies: ['foo-bar'] }).save(),
				(err) => {
					expect(err).toHaveProperty(
						'message',
						'policy foo-bar not configured'
					);
					return true;
				}
			);
			const saved = await new InitialAccessToken({
				policies: undefined
			}).save();
			TestAdapter.for('InitialAccessToken').syncUpdate(
				this.getTokenJti(saved),
				{
					policies: ['foo-bar']
				}
			);

			return assert.rejects(InitialAccessToken.find(saved), (err) => {
				expect(err).toHaveProperty('message', 'policy foo-bar not configured');
				return true;
			});
		});
	});

	describe('Registration Management & RegistrationAccessToken', () => {
		beforeEach(async function () {
			const iat = await new InitialAccessToken({}).save();
			await this.agent
				.post('/reg')
				.auth(iat, { type: 'bearer' })
				.send({ redirect_uris: ['https://rp.example.com/cb'] })
				.expect(201)
				.expect(
					({
						body: {
							registration_access_token,
							registration_client_uri,
							client_secret_expires_at,
							client_id_issued_at,
							...body
						}
					}) => {
						this.rat = registration_access_token;
						this.url = url.parse(registration_client_uri).pathname;
						this.body = body;
					}
				);
		});

		it('runs the policies when a client is getting updated', async function () {
			TestAdapter.for('RegistrationAccessToken').syncUpdate(
				this.getTokenJti(this.rat),
				{
					policies: ['empty-policy']
				}
			);
			const spy = spyOn(
				ApplicationConfig['registration.policies'],
				'empty-policy'
			);

			await this.agent
				.put(this.url)
				.auth(this.rat, { type: 'bearer' })
				.send(this.body)
				.type('json')
				.expect(200);

			expect(spy).toHaveBeenCalledTimes(1);
		});

		it('allows for policies to set property defaults', async function () {
			ApplicationConfig['registration.policies']['set-default'] = (
				ctx,
				properties
			) => {
				if (!('client_name' in properties)) {
					properties.client_name = 'foobar';
				}
			};
			TestAdapter.for('RegistrationAccessToken').syncUpdate(
				this.getTokenJti(this.rat),
				{
					policies: ['set-default']
				}
			);

			await this.agent
				.put(this.url)
				.auth(this.rat, { type: 'bearer' })
				.send(this.body)
				.type('json')
				.expect(200)
				.expect(({ body }) => {
					expect(body).toHaveProperty('client_name', 'foobar');
				});

			await this.agent
				.put(this.url)
				.auth(this.rat, { type: 'bearer' })
				.send({
					...this.body,
					client_name: 'foobarbaz'
				})
				.type('json')
				.expect(200)
				.expect(({ body }) => {
					expect(body).toHaveProperty('client_name', 'foobarbaz');
				});
		});

		it('allows for policies to force property values', async function () {
			ApplicationConfig['registration.policies']['force-value'] = (
				ctx,
				properties
			) => {
				properties.client_name = 'foobar';
			};
			TestAdapter.for('RegistrationAccessToken').syncUpdate(
				this.getTokenJti(this.rat),
				{
					policies: ['force-value']
				}
			);

			await this.agent
				.put(this.url)
				.auth(this.rat, { type: 'bearer' })
				.send({
					...this.body,
					client_name: 'foobarbaz'
				})
				.type('json')
				.expect(200)
				.expect(({ body }) => {
					expect(body).toHaveProperty('client_name', 'foobar');
				});
		});

		it('allows for policies to validate property values', async function () {
			ApplicationConfig['registration.policies']['throw-error'] = () => {
				throw new errors.InvalidClientMetadata('foo');
			};
			TestAdapter.for('RegistrationAccessToken').syncUpdate(
				this.getTokenJti(this.rat),
				{
					policies: ['throw-error']
				}
			);

			await this.agent
				.put(this.url)
				.auth(this.rat, { type: 'bearer' })
				.send(this.body)
				.type('json')
				.expect(400)
				.expect(({ body }) => {
					expect(body).toHaveProperty('error', 'invalid_client_metadata');
					expect(body).toHaveProperty('error_description', 'foo');
				});
		});

		describe('rotateRegistrationAccessToken', () => {
			before(function () {
				const conf = i(provider).configuration;
				conf.features.registrationManagement = {
					rotateRegistrationAccessToken: true
				};
			});

			after(function () {
				const conf = i(provider).configuration;
				conf.features.registrationManagement = {
					rotateRegistrationAccessToken: false
				};
			});

			it('pushes the same policies down to the rotated registration access token', async function () {
				TestAdapter.for('RegistrationAccessToken').syncUpdate(
					this.getTokenJti(this.rat),
					{
						policies: ['empty-policy']
					}
				);

				const spy = mock();
				provider.once('registration_access_token.saved', spy);

				let value;
				await this.agent
					.put(this.url)
					.auth(this.rat, { type: 'bearer' })
					.send(this.body)
					.type('json')
					.expect(200)
					.expect(({ body }) => {
						value = body.registration_access_token;
					});

				expect(spy).toHaveBeenCalled();
				expect(spy.mock.calls[0][0]).toHaveProperty('policies', [
					'empty-policy'
				]);

				expect(
					await RegistrationAccessToken.find(value)
				).toHaveProperty('policies', ['empty-policy']);
			});
		});

		it('policies must be an array', async function () {
			const saved = await new RegistrationAccessToken({
				policies: undefined
			}).save();
			TestAdapter.for('RegistrationAccessToken').syncUpdate(
				this.getTokenJti(saved),
				{
					policies: null
				}
			);

			return assert.rejects(
				RegistrationAccessToken.find(saved),
				(err) => {
					expect(err).toHaveProperty('message', 'policies must be an array');
					return true;
				}
			);
		});

		it('policies array must have members', async function () {
			const saved = await new RegistrationAccessToken({
				policies: undefined
			}).save();
			TestAdapter.for('RegistrationAccessToken').syncUpdate(
				this.getTokenJti(saved),
				{
					policies: []
				}
			);

			return assert.rejects(
				RegistrationAccessToken.find(saved),
				(err) => {
					expect(err).toHaveProperty('message', 'policies must not be empty');
					return true;
				}
			);
		});

		it('policies members must be strings', async function () {
			const saved = await new RegistrationAccessToken({
				policies: undefined
			}).save();
			TestAdapter.for('RegistrationAccessToken').syncUpdate(
				this.getTokenJti(saved),
				{
					policies: [null]
				}
			);

			return assert.rejects(
				RegistrationAccessToken.find(saved),
				(err) => {
					expect(err).toHaveProperty('message', 'policies must be strings');
					return true;
				}
			);
		});

		it('policies members must be present in the provider configuration', async function () {
			const saved = await new RegistrationAccessToken({
				policies: undefined
			}).save();
			TestAdapter.for('RegistrationAccessToken').syncUpdate(
				this.getTokenJti(saved),
				{
					policies: ['foo-bar']
				}
			);

			return assert.rejects(
				RegistrationAccessToken.find(saved),
				(err) => {
					expect(err).toHaveProperty(
						'message',
						'policy foo-bar not configured'
					);
					return true;
				}
			);
		});
	});
});
