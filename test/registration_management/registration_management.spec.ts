import { describe, it, beforeAll, afterEach, expect, mock } from 'bun:test';

import bootstrap, { agent, getHeader } from '../test_helper.js';
import { provider } from 'lib/provider.js';
import { Client } from 'lib/models/client.js';
import { ISSUER } from 'lib/configs/env.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { RegistrationAccessToken } from 'lib/models/registration_access_token.js';
import Configuration from 'lib/helpers/configuration.js';

const json = { 'content-type': 'application/json' };
const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

const NOGO = [
	'registration_access_token',
	'registration_client_uri',
	'client_secret_expires_at',
	'client_id_issued_at'
];

function omit(obj, keys) {
	const out = { ...obj };
	for (const key of keys) delete out[key];
	return out;
}

function updateProperties(client, props = {}) {
	return Object.assign(omit(client, NOGO), props);
}

async function register(metadata = {}) {
	const { data, status } = await agent.reg.post(
		{ redirect_uris: ['https://client.example.com/cb'], ...metadata },
		{ headers: json }
	);
	expect(status).toBe(201);
	if (!data) throw new Error('expected response data');
	return data;
}

function body(res) {
	return res.error?.value ?? res.data;
}

// Mirrors the suite's legacy `failWith`, adapted to the Eden agent and to RFC 6750:
// the Bearer challenge with error/error_description is asserted on 401 responses (where
// it is mandated), and the realm-only challenge on the 400 "no access token provided"
// case; status + body error/error_description are always checked.
function expectFail(res, code, error, error_description) {
	expect(res.status).toBe(code);
	expect(body(res)).toHaveProperty('error', error);
	expect(body(res)).toHaveProperty('error_description', error_description);

	const wwwAuth = res.headers?.get?.('www-authenticate');
	if (code === 401) {
		expect(wwwAuth).toContain(`Bearer realm="${ISSUER}"`);
		expect(wwwAuth).toContain(`error="${error}"`);
		expect(wwwAuth).toContain(`error_description="${error_description}"`);
	} else if (error_description === 'no access token provided') {
		expect(wwwAuth).toContain(`Bearer realm="${ISSUER}"`);
		expect(wwwAuth).not.toContain('error=');
	}
}

describe('OAuth 2.0 Dynamic Client Registration Management Protocol', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	afterEach(() => {
		mock.restore();
		provider.removeAllListeners('registration_update.success');
		provider.removeAllListeners('registration_delete.success');
		provider.removeAllListeners('registration_access_token.destroyed');
		provider.removeAllListeners('registration_access_token.saved');
	});

	describe('feature flag', () => {
		it('checks registration is also enabled', () => {
			const origMgmt = ApplicationConfig['registrationManagement.enabled'];
			const origReg = ApplicationConfig['registration.enabled'];
			ApplicationConfig['registrationManagement.enabled'] = true;
			ApplicationConfig['registration.enabled'] = false;
			try {
				expect(() => new Configuration({})).toThrow(
					'registrationManagement is only available in conjuction with registration'
				);
			} finally {
				ApplicationConfig['registrationManagement.enabled'] = origMgmt;
				ApplicationConfig['registration.enabled'] = origReg;
			}
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
			expect(getHeader(res.response, 'content-type')).toMatch(/application\/json/);
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
			const spy = mock();
			provider.once('registration_update.success', spy);
			const res = await agent
				.reg({ clientId: client.client_id })
				.put(updateProperties(client), {
					headers: { ...json, ...bearer(client.registration_access_token) }
				});
			expect(res.status).toBe(200);
			expect(spy).toHaveBeenCalledTimes(1);
		});

		for (const field of NOGO) {
			it(`must not contain ${field}`, async () => {
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

		it('cannot update non-dynamic clients', async () => {
			const rat = new RegistrationAccessToken({ clientId: 'client' });
			const token = await rat.save();
			const client = await Client.find('client');
			const res = await agent.reg({ clientId: 'client' }).put(
				updateProperties(client.metadata(), {
					redirect_uris: ['https://client.example.com/foobar/cb'],
					client_id: 'client'
				}),
				{ headers: { ...json, ...bearer(token) } }
			);
			expectFail(
				res,
				403,
				'invalid_request',
				'client does not have permission to update its record'
			);
		});

		describe('rotateRegistrationAccessToken', () => {
			// Enabled through ApplicationConfig for this block; the sibling "after rotation"
			// describe flips it back so the flag does not leak within the shared bootstrap.
			beforeAll(() => {
				ApplicationConfig[
					'registrationManagement.rotateRegistrationAccessToken'
				] = true;
			});

			it('destroys the old RegistrationAccessToken', async () => {
				const client = await register();
				const spy = mock();
				provider.once('registration_access_token.destroyed', spy);
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
				const saved = mock();
				provider.once('registration_access_token.saved', saved);
				const res = await agent
					.reg({ clientId: client.client_id })
					.put(updateProperties(client), {
						headers: { ...json, ...bearer(client.registration_access_token) }
					});
				expect(res.status).toBe(200);
				expect(saved).toHaveBeenCalledTimes(1);
				if (!res.data) throw new Error('expected response data');
				expect(res.data.registration_access_token).not.toBe(
					client.registration_access_token
				);
				// the newly saved token resolves to the same client
				const rotated = await RegistrationAccessToken.find(
					res.data.registration_access_token
				);
				expect(rotated?.payload.clientId).toBe(client.client_id);
			});
		});

		describe('after rotation (flag restored)', () => {
			beforeAll(() => {
				ApplicationConfig[
					'registrationManagement.rotateRegistrationAccessToken'
				] = false;
			});

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
			const spy = mock();
			provider.once('registration_delete.success', spy);
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

		it('cannot delete non-dynamic clients', async () => {
			const rat = new RegistrationAccessToken({ clientId: 'client' });
			const token = await rat.save();
			const res = await agent
				.reg({ clientId: 'client' })
				.delete(undefined, { headers: bearer(token) });
			expectFail(
				res,
				403,
				'invalid_request',
				'client does not have permission to delete its record'
			);
		});
	});
});
