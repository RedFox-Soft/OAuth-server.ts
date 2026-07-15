import {
	describe,
	it,
	beforeAll,
	afterEach,
	expect,
	spyOn,
	mock
} from 'bun:test';

import bootstrap, { agent, type Setup } from '../test_helper.js';
import epochTime from '../../lib/helpers/epoch_time.ts';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { TestAdapter } from 'test/models.js';

const route = '/auth';
const scope = 'openid';

describe('session exp handling', () => {
	let setup: Setup;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url);
	});

	afterEach(function () {
		mock.restore();
	});

	function authRequest(auth, cookie) {
		return agent.auth.get({ query: auth.params, headers: { cookie } });
	}

	function sessionIdFromResponse(response) {
		const setCookie = response.headers
			.getSetCookie()
			.find((c) => c.startsWith('_session=') && !c.includes('1970'));
		return setCookie?.split('=')[1].split(';')[0];
	}

	it('generates a new session id when an expired session is found by the adapter', async function () {
		const cookie = await setup.login();
		const session = setup.getSession();
		const oldSessionId = setup.getSessionId();
		session.exp = epochTime() - 300;

		spyOn(TestAdapter.for('Session'), 'destroy');
		const auth = new AuthorizationRequest({ scope });

		const { response } = await authRequest(auth, cookie);
		expect(response.status).toBe(303);
		auth.validateInteractionRedirect(response);
		auth.validateInteraction(response, 'login', 'no_session');

		const newSessionId = sessionIdFromResponse(response);
		expect(newSessionId).toBeTruthy();
		expect(newSessionId).not.toBe(oldSessionId);
	});

	describe('clockTolerance', () => {
		it('respects clockTolerance option', async function () {
			const cookie = await setup.login();
			const session = setup.getSession();
			session.exp = epochTime() - 5;

			spyOn(TestAdapter.for('Session'), 'destroy');

			const auth = new AuthorizationRequest({ scope });

			const { response } = await authRequest(auth, cookie);
			expect(response.status).toBe(303);
			auth.validatePresence(response, ['code', 'state']);
			auth.validateState(response);
			auth.validateClientLocation(response);

			expect(TestAdapter.for('Session').destroy).not.toHaveBeenCalled();
		});

		it('generates a new session id when an expired session is found by the adapter', async function () {
			const cookie = await setup.login();
			const session = setup.getSession();
			session.exp = epochTime() - 10;
			const oldSessionId = setup.getSessionId();

			spyOn(TestAdapter.for('Session'), 'destroy');

			const auth = new AuthorizationRequest({ scope });

			const { response } = await authRequest(auth, cookie);
			expect(response.status).toBe(303);
			auth.validateInteractionRedirect(response);
			auth.validateInteraction(response, 'login', 'no_session');

			const newSessionId = sessionIdFromResponse(response);
			expect(newSessionId).toBeTruthy();
			expect(newSessionId).not.toBe(oldSessionId);
		});
	});
});
