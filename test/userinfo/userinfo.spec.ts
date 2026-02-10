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

import provider from '../../lib/index.ts';
import bootstrap, { agent } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';

describe('UserInfo', () => {
	let access_token: string;
	beforeAll(async () => {
		const setup = await bootstrap(import.meta.url)();
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

		const {
			query: { code }
		} = url.parse(response.headers.get('location'), true);

		const { data } = await auth.getToken(code);
		access_token = data.access_token;
	});

	afterEach(() => mock.restore());

	it('jwtUserinfo can only be enabled with userinfo', () => {
		expect(() => {
			provider.init({
				features: {
					jwtUserinfo: { enabled: true },
					userinfo: { enabled: false }
				}
			});
		}).to.throw('jwtUserinfo is only available in conjuction with userinfo');
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

	it('populates ctx.oidc.entities', async function () {
		const spy = spyOn(OIDCContext.prototype, 'entity');

		await agent.userinfo.get({
			headers: {
				authorization: `Bearer ${access_token}`
			}
		});
		const entities = spy.mock.calls.map((call) => call[0]);
		expect(['Client', 'Grant', 'AccessToken', 'Account']).toEqual(
			expect.arrayContaining(entities)
		);
	});

	it('validates access token is found', async function () {
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

	it('validates access token is provided', async function () {
		const { error } = await agent.userinfo.get();
		if (!error) {
			throw new Error('Have to be exception');
		}
		expect(error.status).toBe(422);
		expect(error.value).toEqual({
			error: 'invalid_request',
			error_description: 'no access token provided'
		});
	});

	it('validates the openid scope is present', async function () {
		const at = await new AccessToken({
			client: await Client.find('client')
		}).save();
		spyOn(Client, 'find').mockResolvedValue(undefined);

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

	it('validates a client is still valid for a found token', async function () {
		const at = await new AccessToken({
			client: await Client.find('client'),
			scope: 'openid'
		}).save();
		spyOn(Client, 'find').mockResolvedValue(undefined);

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

	it('validates an account still valid for a found token', async function () {
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
