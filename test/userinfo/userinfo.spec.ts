import {
	describe,
	it,
	beforeAll,
	expect,
	spyOn,
	afterEach,
	mock
} from 'bun:test';
import url from 'node:url';

import bootstrap, { agent } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { validateConfiguration } from 'lib/configs/configuration.js';
import { ApplicationConfig } from 'lib/configs/application.js';

/**
 * @proves UserInfo returns the claims the user allowed and refuses a token that is unknown, out
 * of scope, or whose client or account no longer stands.
 */
describe('UserInfo', () => {
	let access_token: string;
	beforeAll(async () => {
		const setup = await bootstrap(import.meta.url);
		const cookie = await setup.login({
			scope: 'openid email',
			rejectedClaims: ['email_verified']
		});
		const auth = new AuthorizationRequest({
			scope: 'openid email'
		});
		const { response } = await agent.auth.get({
			query: auth.params,
			headers: {
				cookie
			}
		});

		expect(response.status).toBe(303);
		auth.validatePresence(response, ['code', 'state']);
		auth.validateState(response);
		auth.validateClientLocation(response);
		const location = response.headers.get('location');
		if (!location) {
			throw new Error('location header is missing');
		}

		const { code } = url.parse(location, true).query;
		const { data } = await auth.getToken(code);

		if (!data?.access_token) {
			throw new Error('access_token is missing');
		}
		access_token = data.access_token;
	});

	afterEach(() => mock.restore());

	it('jwtUserinfo can only be enabled with userinfo', () => {
		// The dependency guard is part of configuration validation, a pure function of the config
		// handed to it — so the invalid combination is checked directly, with no need to mutate the
		// live ApplicationConfig and restore it afterwards.
		expect(() =>
			validateConfiguration({
				...ApplicationConfig,
				'jwtUserinfo.enabled': true,
				'userinfo.enabled': false
			})
		).toThrow('jwtUserinfo is only available in conjuction with userinfo');
	});

	it('[get] returns 200 OK and user claims except the rejected ones', async function () {
		const { data } = await agent.userinfo.get({
			headers: {
				authorization: `Bearer ${access_token}`
			}
		});
		expect(data).toHaveProperty('sub');
		expect(data).toHaveProperty('email');
		expect(data).not.toHaveProperty('email_verified');
	});

	it('[post] returns 200 OK and user claims except the rejected ones', async function () {
		const { data } = await agent.userinfo.post(null, {
			headers: {
				authorization: `Bearer ${access_token}`
			}
		});
		expect(data).toHaveProperty('sub');
		expect(data).toHaveProperty('email');
		expect(data).not.toHaveProperty('email_verified');
	});

	it('an unknown access token is refused as invalid_token', async function () {
		const { error } = await agent.userinfo.get({
			headers: {
				authorization: `Bearer Loremipsumdolorsitametconsecteturadipisicingelitsed`
			}
		});
		if (!error) {
			throw new Error('Have to be exception');
		}
		expect(error.status).toBe(401);
		expect(error.value).toEqual({
			error: 'invalid_token',
			error_description: 'invalid token provided'
		});
	});

	it('refuses a UserInfo request with no access token', async function () {
		// @ts-expect-error intentionally calling with no args to test the missing-token path
		const { error } = await agent.userinfo.get();
		if (!error) {
			throw new Error('Have to be exception');
		}
		expect(error.status).toBe(400);
		expect(error.value).toEqual({
			error: 'invalid_request',
			error_description: 'no access token provided'
		});
	});

	it('refuses a token whose scope omits openid', async function () {
		const at = await new AccessToken({
			client: await Client.find('client')
		}).save();
		spyOn(Client, 'tryFind').mockResolvedValue(undefined);

		const { error } = await agent.userinfo.get({
			headers: {
				authorization: `Bearer ${at}`
			}
		});
		if (!error) {
			throw new Error('Have to be exception');
		}
		expect(error.status).toBe(403);
		expect(error.value).toEqual({
			error: 'insufficient_scope',
			error_description: 'access token missing openid scope'
		});
	});

	it('refuses a token whose client no longer exists', async function () {
		const at = await new AccessToken({
			client: await Client.find('client'),
			scope: 'openid'
		}).save();
		spyOn(Client, 'tryFind').mockResolvedValue(undefined);

		const { error } = await agent.userinfo.get({
			headers: {
				authorization: `Bearer ${at}`
			}
		});
		if (!error) {
			throw new Error('Have to be exception');
		}
		expect(error.status).toBe(401);
		expect(error.value).toEqual({
			error: 'invalid_token',
			error_description: 'invalid token provided'
		});
	});

	it('refuses a token whose account has been deactivated', async function () {
		const at = await new AccessToken({
			client: await Client.find('client'),
			scope: 'openid',
			accountId: 'notfound'
		}).save();

		const { error } = await agent.userinfo.get({
			headers: {
				authorization: `Bearer ${at}`
			}
		});
		if (!error) {
			throw new Error('Have to be exception');
		}
		expect(error.status).toBe(401);
		expect(error.value).toEqual({
			error: 'invalid_token',
			error_description: 'invalid token provided'
		});
	});
});
