import { strict as assert } from 'node:assert';

import {
	describe,
	it,
	beforeAll,
	afterAll,
	beforeEach,
	afterEach,
	expect,
	mock,
	spyOn
} from 'bun:test';

import bootstrap, { agent, type Setup } from '../test_helper.js';
import provider, { errors } from '../../lib/index.ts';
import Configuration from '../../lib/helpers/configuration.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { InitialAccessToken } from 'lib/models/initial_access_token.js';
import { RegistrationAccessToken } from 'lib/models/registration_access_token.js';
import { TestAdapter } from 'test/models.js';

const json = { 'content-type': 'application/json' };
const bearer = (token) => ({ authorization: `Bearer ${token}` });

// Policies are persisted under `.payload.*` (the top-level accessors were removed with the
// IN_PAYLOAD refactor), so the saved-event instances and find() results expose `payload.policies`.
describe('client registration policies', () => {
	let setup: Setup;
	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
	});
	beforeEach(() => mock.restore());
	afterEach(() => {
		provider.removeAllListeners('initial_access_token.saved');
		provider.removeAllListeners('registration_access_token.saved');
	});

	describe('configuration', () => {
		it('must only be enabled in conjuction with adapter-backed initial access tokens', () => {
			// Feature flags/sub-options are read flat from ApplicationConfig; flipping
			// initialAccessToken off (registration.policies stays configured) trips the guard.
			const prev = ApplicationConfig['registration.initialAccessToken'];
			ApplicationConfig['registration.initialAccessToken'] = false;
			try {
				expect(() => new Configuration({})).toThrow(
					'registration policies are only available in conjuction with adapter-backed initial access tokens'
				);
			} finally {
				ApplicationConfig['registration.initialAccessToken'] = prev;
			}
		});
	});

	describe('Registration & InitialAccessToken', () => {
		it('allows policies to run to be stored on an InitialAccessToken', async () => {
			const spy = mock();
			provider.once('initial_access_token.saved', spy);
			const value = await new InitialAccessToken({
				policies: ['empty-policy']
			}).save();

			expect(spy).toHaveBeenCalled();
			expect(spy.mock.calls[0][0]).toHaveProperty('payload.policies', [
				'empty-policy'
			]);

			expect(await InitialAccessToken.find(value)).toHaveProperty(
				'payload.policies',
				['empty-policy']
			);
		});

		it('runs the policies when a client is getting created', async () => {
			const spy = spyOn(
				ApplicationConfig['registration.policies'],
				'empty-policy'
			);
			const value = await new InitialAccessToken({
				policies: ['empty-policy']
			}).save();

			const res = await agent.reg.post(
				{ redirect_uris: ['https://rp.example.com/cb'] },
				{ headers: { ...json, ...bearer(value) } }
			);
			expect(res.status).toBe(201);

			expect(spy).toHaveBeenCalledTimes(1);
		});

		it('allows for policies to set property defaults', async () => {
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

			let res = await agent.reg.post(
				{ redirect_uris: ['https://rp.example.com/cb'] },
				{ headers: { ...json, ...bearer(value) } }
			);
			expect(res.status).toBe(201);
			expect(res.data).toHaveProperty('id_token_signed_response_alg', 'HS256');

			// ES256 stands in for the original PS256 "different, provided value": this port's test
			// keystore only advertises RS256 for RSA, so PS256 is not a supported id_token alg and
			// would 400 on validation. ES256 (the EC key) is supported and equally exercises the
			// policy leaving an explicitly provided value untouched.
			res = await agent.reg.post(
				{
					redirect_uris: ['https://rp.example.com/cb'],
					id_token_signed_response_alg: 'ES256'
				},
				{ headers: { ...json, ...bearer(value) } }
			);
			expect(res.status).toBe(201);
			expect(res.data).toHaveProperty('id_token_signed_response_alg', 'ES256');
		});

		it('allows for policies to force property values', async () => {
			ApplicationConfig['registration.policies']['force-default'] = (
				ctx,
				properties
			) => {
				properties.id_token_signed_response_alg = 'HS256';
			};

			const value = await new InitialAccessToken({
				policies: ['force-default']
			}).save();

			const res = await agent.reg.post(
				{
					redirect_uris: ['https://rp.example.com/cb'],
					id_token_signed_response_alg: 'PS256'
				},
				{ headers: { ...json, ...bearer(value) } }
			);
			expect(res.status).toBe(201);
			expect(res.data).toHaveProperty('id_token_signed_response_alg', 'HS256');
		});

		it('allows for policies to validate property values', async () => {
			ApplicationConfig['registration.policies']['throw-error'] = () => {
				throw new errors.InvalidClientMetadata('foo');
			};

			const value = await new InitialAccessToken({
				policies: ['throw-error']
			}).save();

			const res = await agent.reg.post(
				{
					redirect_uris: ['https://rp.example.com/cb'],
					id_token_signed_response_alg: 'PS256'
				},
				{ headers: { ...json, ...bearer(value) } }
			);
			expect(res.status).toBe(400);
			const body = res.error?.value ?? res.data;
			expect(body).toHaveProperty('error', 'invalid_client_metadata');
			expect(body).toHaveProperty('error_description', 'foo');
		});

		it('pushes the policy down to the registration access token', async () => {
			const value = await new InitialAccessToken({
				policies: ['empty-policy']
			}).save();

			const spy = mock();
			provider.once('registration_access_token.saved', spy);

			const res = await agent.reg.post(
				{ redirect_uris: ['https://rp.example.com/cb'] },
				{ headers: { ...json, ...bearer(value) } }
			);
			expect(res.status).toBe(201);

			expect(spy).toHaveBeenCalledTimes(1);
			expect(spy.mock.calls[0][0]).toHaveProperty('payload.policies', [
				'empty-policy'
			]);
		});

		it('can be done to push different policies to rat', async () => {
			ApplicationConfig['registration.policies']['change-rat-policy'] = async (
				ctx
			) => {
				// Token fields live under `.payload.*` in this port, so mutate the entity's
				// payload rather than a top-level `.policies` accessor (which no longer exists).
				ctx.oidc.entities.RegistrationAccessToken.payload.policies = [
					'empty-policy'
				];
			};

			const value = await new InitialAccessToken({
				policies: ['change-rat-policy']
			}).save();

			const spy = mock();
			provider.once('registration_access_token.saved', spy);

			const res = await agent.reg.post(
				{ redirect_uris: ['https://rp.example.com/cb'] },
				{ headers: { ...json, ...bearer(value) } }
			);
			expect(res.status).toBe(201);

			expect(spy).toHaveBeenCalledTimes(1);
			expect(spy.mock.calls[0][0]).toHaveProperty('payload.policies', [
				'empty-policy'
			]);
		});

		it('policies must be an array', async () => {
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
				setup.getTokenJti(saved),
				{
					policies: null
				}
			);

			return assert.rejects(InitialAccessToken.find(saved), (err) => {
				expect(err).toHaveProperty('message', 'policies must be an array');
				return true;
			});
		});

		it('policies array must have members', async () => {
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
				setup.getTokenJti(saved),
				{
					policies: []
				}
			);

			return assert.rejects(InitialAccessToken.find(saved), (err) => {
				expect(err).toHaveProperty('message', 'policies must not be empty');
				return true;
			});
		});

		it('policies members must be strings', async () => {
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
				setup.getTokenJti(saved),
				{
					policies: [null]
				}
			);

			return assert.rejects(InitialAccessToken.find(saved), (err) => {
				expect(err).toHaveProperty('message', 'policies must be strings');
				return true;
			});
		});

		it('policies members must be present in the provider configuration', async () => {
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
				setup.getTokenJti(saved),
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
		let rat;
		let clientId;
		let body;

		beforeEach(async () => {
			const iat = await new InitialAccessToken({}).save();
			const res = await agent.reg.post(
				{ redirect_uris: ['https://rp.example.com/cb'] },
				{ headers: { ...json, ...bearer(iat) } }
			);
			expect(res.status).toBe(201);
			const {
				registration_access_token,
				registration_client_uri,
				client_secret_expires_at,
				client_id_issued_at,
				...rest
			} = res.data;
			rat = registration_access_token;
			clientId = rest.client_id;
			body = rest;
		});

		it('runs the policies when a client is getting updated', async () => {
			TestAdapter.for('RegistrationAccessToken').syncUpdate(
				setup.getTokenJti(rat),
				{ policies: ['empty-policy'] }
			);
			const spy = spyOn(
				ApplicationConfig['registration.policies'],
				'empty-policy'
			);

			const res = await agent
				.reg({ clientId })
				.put(body, { headers: { ...json, ...bearer(rat) } });
			expect(res.status).toBe(200);

			expect(spy).toHaveBeenCalledTimes(1);
		});

		it('allows for policies to set property defaults', async () => {
			ApplicationConfig['registration.policies']['set-default'] = (
				ctx,
				properties
			) => {
				if (!('client_name' in properties)) {
					properties.client_name = 'foobar';
				}
			};
			TestAdapter.for('RegistrationAccessToken').syncUpdate(
				setup.getTokenJti(rat),
				{ policies: ['set-default'] }
			);

			let res = await agent
				.reg({ clientId })
				.put(body, { headers: { ...json, ...bearer(rat) } });
			expect(res.status).toBe(200);
			expect(res.data).toHaveProperty('client_name', 'foobar');

			res = await agent
				.reg({ clientId })
				.put(
					{ ...body, client_name: 'foobarbaz' },
					{ headers: { ...json, ...bearer(rat) } }
				);
			expect(res.status).toBe(200);
			expect(res.data).toHaveProperty('client_name', 'foobarbaz');
		});

		it('allows for policies to force property values', async () => {
			ApplicationConfig['registration.policies']['force-value'] = (
				ctx,
				properties
			) => {
				properties.client_name = 'foobar';
			};
			TestAdapter.for('RegistrationAccessToken').syncUpdate(
				setup.getTokenJti(rat),
				{ policies: ['force-value'] }
			);

			const res = await agent
				.reg({ clientId })
				.put(
					{ ...body, client_name: 'foobarbaz' },
					{ headers: { ...json, ...bearer(rat) } }
				);
			expect(res.status).toBe(200);
			expect(res.data).toHaveProperty('client_name', 'foobar');
		});

		it('allows for policies to validate property values', async () => {
			ApplicationConfig['registration.policies']['throw-error'] = () => {
				throw new errors.InvalidClientMetadata('foo');
			};
			TestAdapter.for('RegistrationAccessToken').syncUpdate(
				setup.getTokenJti(rat),
				{ policies: ['throw-error'] }
			);

			const res = await agent
				.reg({ clientId })
				.put(body, { headers: { ...json, ...bearer(rat) } });
			expect(res.status).toBe(400);
			const errorBody = res.error?.value ?? res.data;
			expect(errorBody).toHaveProperty('error', 'invalid_client_metadata');
			expect(errorBody).toHaveProperty('error_description', 'foo');
		});

		describe('rotateRegistrationAccessToken', () => {
			beforeAll(() => {
				ApplicationConfig[
					'registrationManagement.rotateRegistrationAccessToken'
				] = true;
			});

			afterAll(() => {
				ApplicationConfig[
					'registrationManagement.rotateRegistrationAccessToken'
				] = false;
			});

			it('pushes the same policies down to the rotated registration access token', async () => {
				TestAdapter.for('RegistrationAccessToken').syncUpdate(
					setup.getTokenJti(rat),
					{ policies: ['empty-policy'] }
				);

				const spy = mock();
				provider.once('registration_access_token.saved', spy);

				const res = await agent
					.reg({ clientId })
					.put(body, { headers: { ...json, ...bearer(rat) } });
				expect(res.status).toBe(200);
				const value = res.data.registration_access_token;

				expect(spy).toHaveBeenCalled();
				expect(spy.mock.calls[0][0]).toHaveProperty('payload.policies', [
					'empty-policy'
				]);

				expect(await RegistrationAccessToken.find(value)).toHaveProperty(
					'payload.policies',
					['empty-policy']
				);
			});
		});

		it('policies must be an array', async () => {
			const saved = await new RegistrationAccessToken({
				policies: undefined
			}).save();
			TestAdapter.for('RegistrationAccessToken').syncUpdate(
				setup.getTokenJti(saved),
				{ policies: null }
			);

			return assert.rejects(RegistrationAccessToken.find(saved), (err) => {
				expect(err).toHaveProperty('message', 'policies must be an array');
				return true;
			});
		});

		it('policies array must have members', async () => {
			const saved = await new RegistrationAccessToken({
				policies: undefined
			}).save();
			TestAdapter.for('RegistrationAccessToken').syncUpdate(
				setup.getTokenJti(saved),
				{ policies: [] }
			);

			return assert.rejects(RegistrationAccessToken.find(saved), (err) => {
				expect(err).toHaveProperty('message', 'policies must not be empty');
				return true;
			});
		});

		it('policies members must be strings', async () => {
			const saved = await new RegistrationAccessToken({
				policies: undefined
			}).save();
			TestAdapter.for('RegistrationAccessToken').syncUpdate(
				setup.getTokenJti(saved),
				{ policies: [null] }
			);

			return assert.rejects(RegistrationAccessToken.find(saved), (err) => {
				expect(err).toHaveProperty('message', 'policies must be strings');
				return true;
			});
		});

		it('policies members must be present in the provider configuration', async () => {
			const saved = await new RegistrationAccessToken({
				policies: undefined
			}).save();
			TestAdapter.for('RegistrationAccessToken').syncUpdate(
				setup.getTokenJti(saved),
				{ policies: ['foo-bar'] }
			);

			return assert.rejects(RegistrationAccessToken.find(saved), (err) => {
				expect(err).toHaveProperty('message', 'policy foo-bar not configured');
				return true;
			});
		});
	});
});
