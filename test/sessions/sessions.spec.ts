import { describe, it, beforeAll, afterEach, expect } from 'bun:test';
import sinon from 'sinon';

import bootstrap, { agent } from '../test_helper.js';
import epochTime from '../../lib/helpers/epoch_time.ts';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { TestAdapter } from 'test/models.js';

const route = '/auth';
const scope = 'openid';

describe('session exp handling', () => {
	let setup = null;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url)();
	});

	afterEach(function () {
		sinon.restore();
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

		sinon.spy(TestAdapter.for('Session'), 'destroy');
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

			sinon.spy(TestAdapter.for('Session'), 'destroy');

			const auth = new AuthorizationRequest({ scope });

			const { response } = await authRequest(auth, cookie);
			expect(response.status).toBe(303);
			auth.validatePresence(response, ['code', 'state']);
			auth.validateState(response);
			auth.validateClientLocation(response);

			expect(TestAdapter.for('Session').destroy.called).toBe(false);
		});

		it('generates a new session id when an expired session is found by the adapter', async function () {
			const cookie = await setup.login();
			const session = setup.getSession();
			session.exp = epochTime() - 10;
			const oldSessionId = setup.getSessionId();

			sinon.spy(TestAdapter.for('Session'), 'destroy');

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
