import sinon from 'sinon';
import { expect } from 'chai';

import bootstrap from '../test_helper.js';
import epochTime from '../../lib/helpers/epoch_time.ts';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { TestAdapter } from 'test/models.js';

const route = '/auth';
const scope = 'openid';
const verb = 'get';

describe('session exp handling', () => {
	before(bootstrap(import.meta.url));

	afterEach(function () {
		sinon.restore();
	});
	afterEach(function () {
		return this.logout();
	});

	it('generates a new session id when an expired session is found by the adapter', async function () {
		await this.login();
		const session = this.getSession();
		const oldSessionId = this.getSessionId();
		session.exp = epochTime() - 300;

		sinon.spy(TestAdapter.for('Session'), 'destroy');
		const auth = new AuthorizationRequest({ scope });

		await this.wrap({ route, verb, auth })
			.expect(303)
			.expect(auth.validateInteractionRedirect)
			.expect(auth.validateInteraction('login', 'no_session'));

		const newSessionId = this.getSessionId();
		expect(newSessionId).to.be.ok;
		expect(newSessionId).not.to.equal(oldSessionId);
	});

	describe('clockTolerance', () => {
		it('respects clockTolerance option', async function () {
			await this.login();
			const session = this.getSession();
			session.exp = epochTime() - 5;

			sinon.spy(TestAdapter.for('Session'), 'destroy');

			const auth = new AuthorizationRequest({ scope });

			await this.wrap({ route, verb, auth })
				.expect(303)
				.expect(auth.validatePresence(['code', 'state']))
				.expect(auth.validateState)
				.expect(auth.validateClientLocation);

			expect(TestAdapter.for('Session').destroy.called).to.be.false;
		});

		it('generates a new session id when an expired session is found by the adapter', async function () {
			await this.login();
			const session = this.getSession();
			session.exp = epochTime() - 10;
			const oldSessionId = this.getSessionId();

			sinon.spy(TestAdapter.for('Session'), 'destroy');

			const auth = new AuthorizationRequest({ scope });

			await this.wrap({ route, verb, auth })
				.expect(303)
				.expect(auth.validateInteractionRedirect)
				.expect(auth.validateInteraction('login', 'no_session'));

			const newSessionId = this.getSessionId();
			expect(newSessionId).to.be.ok;
			expect(newSessionId).not.to.equal(oldSessionId);
		});
	});
});
