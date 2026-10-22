import {
	describe,
	it,
	beforeAll,
	afterAll,
	afterEach,
	expect,
	mock
} from 'bun:test';

import bootstrap, { agent, getHeader, seedClient } from '../test_helper.js';
import nanoid from 'lib/helpers/nanoid.ts';
import { eventBus, type ServerListener } from 'lib/event_bus.js';
import { Client, toStored } from 'lib/models/client.js';
import { ISSUER } from 'lib/configs/env.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { RegistrationAccessToken } from 'lib/models/registration_access_token.js';
import { validateConfiguration } from 'lib/configs/configuration.js';
import type { RegistrationResponse } from 'lib/shared/response_schemas.js';
import type { Static } from 'elysia';

const json = { 'content-type': 'application/json' };
const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

const NOGO = [
	'registration_access_token',
	'registration_client_uri',
	'client_secret_expires_at',
	'client_id_issued_at'
];

function omit(obj: Record<string, unknown>, keys: string[]) {
	const out = { ...obj };
	for (const key of keys) delete out[key];
	return out;
}

function updateProperties(
	client: Record<string, unknown>,
	props: Record<string, unknown> = {}
) {
	return Object.assign(omit(client, NOGO), props);
}

// A registered client as the response describes it, with the registration access token it was issued.
type RegisteredClient = Record<string, unknown> &
	Static<typeof RegistrationResponse> & { registration_access_token: string };

async function register(metadata = {}): Promise<RegisteredClient> {
	const { data, status } = await agent.reg.post(
		{ redirect_uris: ['https://client.example.com/cb'], ...metadata },
		{ headers: json }
	);
	expect(status).toBe(201);
	if (!data?.registration_access_token) {
		throw new Error('expected a registration access token');
	}
	return { ...data, registration_access_token: data.registration_access_token };
}

// What these cases read off a typed-client result.
type Result = {
	status: number;
	data?: unknown;
	error?: { value: unknown } | null;
	response?: Response;
};

function body(res: Result) {
	return res.error?.value ?? res.data;
}

// Mirrors the suite's legacy `failWith`, adapted to the Eden agent and to RFC 6750:
// the Bearer challenge with error/error_description is asserted on 401 responses (where
// it is mandated), and the realm-only challenge on the 400 "no access token provided"
// case; status + body error/error_description are always checked.
function expectFail(
	res: Result,
	code: number,
	error: string,
	error_description: string
) {
	expect(res.status).toBe(code);
	expect(body(res)).toHaveProperty('error', error);
	expect(body(res)).toHaveProperty('error_description', error_description);

	const wwwAuth = res.response?.headers.get('www-authenticate');
	if (code === 401) {
		expect(wwwAuth).toContain(`Bearer realm="${ISSUER}"`);
		expect(wwwAuth).toContain(`error="${error}"`);
		expect(wwwAuth).toContain(`error_description="${error_description}"`);
	} else if (error_description === 'no access token provided') {
		expect(wwwAuth).toContain(`Bearer realm="${ISSUER}"`);
		expect(wwwAuth).not.toContain('error=');
	}
}

/**
 * @proves A client manages its own registration with the token it was issued, sees its own
 * metadata without internal fields, and has that token rotated and the old one destroyed.
 */
describe('OAuth 2.0 Dynamic Client Registration Management Protocol', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	afterEach(() => {
		mock.restore();
		eventBus.removeAllListeners('registration_update.success');
		eventBus.removeAllListeners('registration_delete.success');
		eventBus.removeAllListeners('registration_access_token.destroyed');
		eventBus.removeAllListeners('registration_access_token.saved');
	});

	describe('feature flag', () => {
		it('the management endpoints are unreachable while registration itself is off', () => {
			// Validation is a pure function of the config handed to it, so the invalid combination is
			// checked on a copy rather than by mutating the live settings and restoring them.
			expect(() =>
				validateConfiguration({
					...ApplicationConfig,
					'registrationManagement.enabled': true,
					'registration.enabled': false
				})
			).toThrow(
				'registrationManagement is only available in conjuction with registration'
			);
		});
	});

	describe('Client Update Request', () => {
		it('responds w/ 200 JSON and nocache headers', async () => {
			const client = await register();
			const res = await agent.reg({ clientId: client.client_id }).put(
				updateProperties(client, {
					redirect_uris: ['https://client.example.com/foobar/cb']
				}),
				{ headers: { ...json, ...bearer(client.registration_access_token) } }
			);

			expect(res.status).toBe(200);
			expect(getHeader(res.response, 'content-type')).toMatch(
				/application\/json/
			);
			expect(getHeader(res.response, 'cache-control')).toBe('no-store');
			expect(res.data).toHaveProperty(
				'registration_access_token',
				client.registration_access_token
			);
			expect(res.data).toHaveProperty(
				'registration_client_uri',
				client.registration_client_uri
			);
			expect(res.data).toHaveProperty(
				'client_secret_expires_at',
				client.client_secret_expires_at
			);
			expect(res.data).toHaveProperty(
				'client_id_issued_at',
				client.client_id_issued_at
			);
			if (!res.data) throw new Error('expected response data');
			expect(res.data.redirect_uris).toEqual([
				'https://client.example.com/foobar/cb'
			]);
		});

		it('rejects calls with bad registration access token', async () => {
			const client = await register();
			const res = await agent
				.reg({ clientId: client.client_id })
				.put(updateProperties(client), { headers: bearer('foobarbaz') });
			expectFail(res, 401, 'invalid_token', 'invalid token provided');
		});

		it('rejects calls with no registration access token', async () => {
			const client = await register();
			const res = await agent
				.reg({ clientId: client.client_id })
				.put(updateProperties(client), { headers: json });
			expectFail(res, 400, 'invalid_request', 'no access token provided');
		});

		it('populates the Client and RegistrationAccessToken (returns the RAT + client_uri)', async () => {
			const client = await register();
			const res = await agent
				.reg({ clientId: client.client_id })
				.put(updateProperties(client), {
					headers: { ...json, ...bearer(client.registration_access_token) }
				});
			expect(res.status).toBe(200);
			expect(res.data).toHaveProperty(
				'registration_access_token',
				client.registration_access_token
			);
			expect(res.data).toHaveProperty('registration_client_uri');
		});

		it('allows for properties to be deleted', async () => {
			const client = await register({ userinfo_signed_response_alg: 'RS256' });
			const res = await agent
				.reg({ clientId: client.client_id })
				.put(updateProperties(client, { userinfo_signed_response_alg: null }), {
					headers: { ...json, ...bearer(client.registration_access_token) }
				});
			expect(res.status).toBe(200);
			expect(res.data).not.toHaveProperty('userinfo_signed_response_alg');
		});

		it('allows for properties to be deleted (not client_secret tho)', async () => {
			const client = await register();
			const res = await agent
				.reg({ clientId: client.client_id })
				.put(updateProperties(client, { client_secret: null }), {
					headers: { ...json, ...bearer(client.registration_access_token) }
				});
			expectFail(
				res,
				400,
				'invalid_request',
				"provided client_secret does not match the authenticated client's one"
			);
		});

		it('allows for properties to be deleted by omission', async () => {
			const client = await register({ userinfo_signed_response_alg: 'RS256' });
			delete client.userinfo_signed_response_alg;
			const res = await agent
				.reg({ clientId: client.client_id })
				.put(updateProperties(client), {
					headers: { ...json, ...bearer(client.registration_access_token) }
				});
			expect(res.status).toBe(200);
			expect(res.data).not.toHaveProperty('userinfo_signed_response_alg');
		});

		it('provides a secret if suddently needed', async () => {
			const client = await register({
				token_endpoint_auth_method: 'none',
				response_types: ['code'],
				grant_types: ['authorization_code']
			});
			expect(client).not.toHaveProperty('client_secret');
			const res = await agent.reg({ clientId: client.client_id }).put(
				updateProperties(client, {
					response_types: ['code'],
					grant_types: ['authorization_code'],
					token_endpoint_auth_method: 'client_secret_basic'
				}),
				{ headers: { ...json, ...bearer(client.registration_access_token) } }
			);
			expect(res.status).toBe(200);
			expect(res.data).toHaveProperty('client_secret');
			expect(res.data).toHaveProperty('client_secret_expires_at');
		});

		it('emits an event', async () => {
			const client = await register();
			const spy = mock<ServerListener<'registration_update.success'>>();
			eventBus.once('registration_update.success', spy);
			const res = await agent
				.reg({ clientId: client.client_id })
				.put(updateProperties(client), {
					headers: { ...json, ...bearer(client.registration_access_token) }
				});
			expect(res.status).toBe(200);
			expect(spy).toHaveBeenCalledTimes(1);
		});

		for (const field of NOGO) {
			it(`the response never carries the internal fields, for every one of them`, async () => {
				const client = await register();
				const res = await agent.reg({ clientId: client.client_id }).put(
					updateProperties(client, {
						redirect_uris: ['https://client.example.com/foobar/cb'],
						[field]: 'foobar'
					}),
					{ headers: { ...json, ...bearer(client.registration_access_token) } }
				);
				expectFail(
					res,
					400,
					'invalid_request',
					`request MUST NOT include the ${field} field`
				);
			});
		}

		it('can update any stored client given a valid registration access token', async () => {
			// Clients are single-sourced from the adapter and uniformly manageable
			// (there is no `noManage` static-client class any more); a valid RAT is
			// the only gate.
			const rat = new RegistrationAccessToken({ clientId: 'client' });
			const token = await rat.save();
			const client = await Client.find('client');
			const res = await agent.reg({ clientId: 'client' }).put(
				updateProperties(toStored(client), {
					redirect_uris: ['https://client.example.com/foobar/cb'],
					client_id: 'client'
				}),
				{ headers: { ...json, ...bearer(token) } }
			);
			expect(res.status).toBe(200);
			if (!res.data) throw new Error('expected response data');
			expect(res.data.redirect_uris).toEqual([
				'https://client.example.com/foobar/cb'
			]);
		});

		describe('rotateRegistrationAccessToken', () => {
			/*
			 * On for this block only, and put back by the block itself: cases run in any order, so a sibling
			 * that switched it off again could run first and leave it on for every case after this block.
			 */
			const ROTATE = 'registrationManagement.rotateRegistrationAccessToken';
			let before: (typeof ApplicationConfig)[typeof ROTATE];
			beforeAll(() => {
				before = ApplicationConfig[ROTATE];
				ApplicationConfig[ROTATE] = true;
			});
			afterAll(() => {
				ApplicationConfig[ROTATE] = before;
			});

			it('destroys the old RegistrationAccessToken', async () => {
				const client = await register();
				const spy =
					mock<ServerListener<'registration_access_token.destroyed'>>();
				eventBus.once('registration_access_token.destroyed', spy);
				const res = await agent
					.reg({ clientId: client.client_id })
					.put(updateProperties(client), {
						headers: { ...json, ...bearer(client.registration_access_token) }
					});
				expect(res.status).toBe(200);
				expect(spy).toHaveBeenCalledTimes(1);
			});

			it('issues and returns a new, different RegistrationAccessToken', async () => {
				const client = await register();
				const saved = mock<ServerListener<'registration_access_token.saved'>>();
				eventBus.once('registration_access_token.saved', saved);
				const res = await agent
					.reg({ clientId: client.client_id })
					.put(updateProperties(client), {
						headers: { ...json, ...bearer(client.registration_access_token) }
					});
				expect(res.status).toBe(200);
				expect(saved).toHaveBeenCalledTimes(1);
				if (!res.data?.registration_access_token) {
					throw new Error('expected a rotated registration access token');
				}
				expect(res.data.registration_access_token).not.toBe(
					client.registration_access_token
				);
				// the newly saved token resolves to the same client
				const rotated = await RegistrationAccessToken.find(
					res.data.registration_access_token
				);
				expect(rotated.payload.clientId).toBe(client.client_id);
			});
		});

		describe('with rotation off', () => {
			it('does not rotate when disabled', async () => {
				const client = await register();
				const res = await agent
					.reg({ clientId: client.client_id })
					.put(updateProperties(client), {
						headers: { ...json, ...bearer(client.registration_access_token) }
					});
				expect(res.status).toBe(200);
				if (!res.data) throw new Error('expected response data');
				expect(res.data.registration_access_token).toBe(
					client.registration_access_token
				);
			});
		});
	});

	describe('Client Delete Request', () => {
		it('responds w/ empty 204 and nocache headers and removes the registration access token', async () => {
			const client = await register();
			const res = await agent
				.reg({ clientId: client.client_id })
				.delete(undefined, {
					headers: bearer(client.registration_access_token)
				});

			expect(res.status).toBe(204);
			expect(getHeader(res.response, 'cache-control')).toBe('no-store');
			expect(
				await RegistrationAccessToken.tryFind(client.registration_access_token)
			).toBeUndefined();
		});

		it('emits an event', async () => {
			const client = await register();
			const spy = mock<ServerListener<'registration_delete.success'>>();
			eventBus.once('registration_delete.success', spy);
			const res = await agent
				.reg({ clientId: client.client_id })
				.delete(undefined, {
					headers: bearer(client.registration_access_token)
				});
			expect(res.status).toBe(204);
			expect(spy).toHaveBeenCalledTimes(1);
		});

		it('rejects calls with bad registration access token', async () => {
			const client = await register();
			const res = await agent
				.reg({ clientId: client.client_id })
				.delete(undefined, { headers: bearer('foobarbaz') });
			expectFail(res, 401, 'invalid_token', 'invalid token provided');
		});

		it('rejects calls with no registration access token', async () => {
			const client = await register();
			const res = await agent.reg({ clientId: client.client_id }).delete();
			expectFail(res, 400, 'invalid_request', 'no access token provided');
		});

		it('can delete any stored client given a valid registration access token', async () => {
			// All clients are manageable now (no `noManage` class); a valid RAT is
			// the only gate. A stored client of its own, so the one the update case reads is not deleted.
			const clientId = `stored-${nanoid()}`;
			seedClient({
				clientId,
				clientSecret: 'secret',
				redirectUris: ['https://client.example.com/cb']
			});
			const rat = new RegistrationAccessToken({ clientId });
			const token = await rat.save();
			const res = await agent
				.reg({ clientId })
				.delete(undefined, { headers: bearer(token) });
			expect(res.status).toBe(204);
		});
	});

	/*
	 * MCP 2026-07-28: "All redirect URIs MUST be either localhost or use HTTPS". Plain http is for a program on
	 * the end user's own machine; anywhere else it hands the code to whoever is on the network path.
	 */
	describe('a plain-http redirect on a host that is not loopback', () => {
		it('is refused at registration, naming the address', async () => {
			const res = await agent.reg.post(
				{ redirect_uris: ['http://intranet.example/callback'] },
				{ headers: json }
			);

			expect(res.status).toBe(400);
			expect(body(res)).toMatchObject({ error: 'invalid_redirect_uri' });
			expect(JSON.stringify(body(res))).toContain(
				'http://intranet.example/callback'
			);
		});

		it('is admitted at registration on a loopback host', async () => {
			const res = await agent.reg.post(
				{ redirect_uris: ['http://localhost:3000/callback'] },
				{ headers: json }
			);

			expect(res.status).toBe(201);
		});

		it('is refused as a post-logout redirect at registration', async () => {
			const res = await agent.reg.post(
				{
					redirect_uris: ['https://client.example.com/cb'],
					post_logout_redirect_uris: ['http://intranet.example/bye']
				},
				{ headers: json }
			);

			expect(res.status).toBe(400);
			expect(body(res)).toMatchObject({ error: 'invalid_client_metadata' });
		});

		it('is refused when an update adds it, leaving the registration as it was', async () => {
			const client = await register();
			await agent.reg({ clientId: client.client_id }).put(
				updateProperties(client, {
					redirect_uris: [
						'https://client.example.com/cb',
						'http://intranet.example/callback'
					]
				}),
				{ headers: { ...json, ...bearer(client.registration_access_token) } }
			);

			const read = await agent
				.reg({ clientId: client.client_id })
				.get({ headers: bearer(client.registration_access_token) });

			expect(read.status).toBe(200);
			expect((read.data as { redirect_uris?: string[] }).redirect_uris).toEqual(
				['https://client.example.com/cb']
			);
		});

		it('refuses the update that adds it', async () => {
			const client = await register();

			const res = await agent.reg({ clientId: client.client_id }).put(
				updateProperties(client, {
					redirect_uris: [
						'https://client.example.com/cb',
						'http://intranet.example/callback'
					]
				}),
				{ headers: { ...json, ...bearer(client.registration_access_token) } }
			);

			expect(res.status).toBe(400);
			expect(body(res)).toMatchObject({ error: 'invalid_redirect_uri' });
		});
	});
});
