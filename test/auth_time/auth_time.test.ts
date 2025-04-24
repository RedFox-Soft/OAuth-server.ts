import url from 'node:url';
import {
	describe,
	it,
	beforeAll,
	afterAll,
	expect,
	mock,
	spyOn
} from 'bun:test';
import { decodeJwt } from 'jose';
import bootstrap from '../test_helper.ts';

const { info, warn } = console;
console.info = function (...args) {
	if (!args[0].includes('NOTICE: ')) info.apply(this, args);
};
console.warn = function (...args) {
	if (!args[0].includes('WARNING: ')) warn.apply(this, args);
};

describe('responds with a id_token containing auth_time', () => {
	let setup = null;
	let cookie = null;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url)();
		cookie = await setup.login();
	});

	afterAll(() => {
		setup.TestAdapter.clear();
	});

	async function getIdToken(options = {}) {
		const auth = new setup.AuthorizationRequest({
			response_type: 'code',
			scope: 'openid',
			...options
		});

		const { response } = await setup.agent.auth.get({
			query: auth,
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
		return data.id_token;
	}

	it('when max_age was present in the request', async function () {
		const id_token = await getIdToken({ max_age: 999 });
		expect(decodeJwt(id_token)).toHaveProperty('auth_time');
	});

	describe('special cases', () => {
		beforeAll(function () {
			spyOn(
				setup.provider.OIDCContext.prototype,
				'promptPending'
			).mockReturnValue(false);
		});

		afterAll(() => {
			mock.restore();
		});

		it('when prompt=login was requested', async function () {
			const id_token = await getIdToken({ prompt: 'login' });
			expect(decodeJwt(id_token)).toHaveProperty('auth_time');
		});

		it('when max_age=0 was requested', async function () {
			const id_token = await getIdToken({ max_age: 0 });
			expect(decodeJwt(id_token)).toHaveProperty('auth_time');
		});

		it('when client has default_max_age=0', async function () {
			const id_token = await getIdToken({
				client_id: 'client-with-default_max_age-zero'
			});
			expect(decodeJwt(id_token)).toHaveProperty('auth_time');
		});
	});

	it('when client has require_auth_time', async function () {
		const id_token = await getIdToken({
			client_id: 'client-with-require_auth_time'
		});
		expect(decodeJwt(id_token)).toHaveProperty('auth_time');
	});

	it('when client has default_max_age', async function () {
		const id_token = await getIdToken({
			client_id: 'client-with-default_max_age'
		});
		expect(decodeJwt(id_token)).toHaveProperty('auth_time');
	});
});
