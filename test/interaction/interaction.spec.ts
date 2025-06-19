import sinon from 'sinon';

import {
	describe,
	it,
	beforeAll,
	afterEach,
	beforeEach,
	expect
} from 'bun:test';
import nanoid from '../../lib/helpers/nanoid.ts';
import bootstrap, { agent } from '../test_helper.js';
import epochTime from '../../lib/helpers/epoch_time.ts';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { provider } from 'lib/index.js';
import { Session } from 'lib/models/session.js';

const expire = new Date();
expire.setDate(expire.getDate() + 1);

describe('devInteractions', () => {
	let setup = null;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url)();
	});
	afterEach(function () {
		sinon.restore();
	});

	describe('render login', () => {
		let object = {};

		beforeEach(async function () {
			const auth = new AuthorizationRequest({
				scope: 'openid'
			});

			const { response } = await agent.auth.get({
				query: auth.params
			});

			const url = response.headers.get('location');
			const [, uid] = url.split('/');

			object.cookie = response.headers.get('set-cookie');
			object.uid = uid;
			object.url = url;
		});

		it('with a form', async function () {
			const uid = object.uid;
			const { data } = await agent.ui[uid].login.get({
				headers: {
					cookie: object.cookie
				}
			});

			expect(object.url).toEndWith('/login');
			expect(data).toContain('method="post"');
			expect(data).toContain(`action="/ui/${uid}/login`);
		});

		it('"handles" not found interaction session id cookie', async function () {
			const { error } = await agent.ui[object.uid].login.get();

			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description: 'Invalid interaction cookie'
			});
		});

		it('"handles" not found interaction session', async function () {
			sinon.stub(provider.Interaction, 'find').resolves();

			const { error } = await agent.ui[object.uid].login.get({
				headers: {
					cookie: object.cookie
				}
			});
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description: 'interaction session not found'
			});
		});
	});

	describe.skip('render interaction', () => {
		let uid = null;

		beforeEach(async function () {
			const cookie = setup.login();
			const auth = new AuthorizationRequest({
				scope: 'openid',
				prompt: 'consent'
			});

			const { response } = await agent.auth.get({
				query: auth.params,
				headers: {
					cookie
				}
			});
			const url = response.headers.get('location');
			[, uid] = url.split('/');
		});

		it('with a form', async function () {
			const { data } = await agent.ui[uid].login.get();

			return agent
				.get(url)
				.expect(200)
				.expect(new RegExp(`action="${this.provider.issuer}${this.url}"`))
				.expect(/name="prompt" value="consent"/)
				.expect(/Authorize/);
		});

		it('checks that the authentication session is still there', async function () {
			const session = this.getSession({ instantiate: true });
			await session.destroy();

			await this.agent
				.get(this.url)
				.accept('text/html')
				.expect(400)
				.expect('content-type', 'text/html; charset=utf-8')
				.expect(/session not found/);
		});

		it("checks that the authentication session's principal didn't change", async function () {
			const session = this.getSession({ instantiate: true });
			session.accountId = 'foobar';
			await session.persist();

			await this.agent
				.get(this.url)
				.accept('text/html')
				.expect(400)
				.expect('content-type', 'text/html; charset=utf-8')
				.expect(/session principal changed/);
		});
	});

	describe.skip('when unimplemented prompt is requested', () => {
		it('throws a 501', async function () {
			const auth = new AuthorizationRequest({
				scope: 'openid'
			});

			const url = await this.agent
				.get('/auth')
				.query(auth)
				.then((response) => response.headers.location);

			const split = url.split('/');
			const uid = split[split.length - 1];
			const interaction = this.TestAdapter.for('Interaction').syncFind(uid);
			interaction.prompt.name = 'notimplemented';

			return this.agent.get(url).expect(501);
		});
	});

	describe('navigate to abort', () => {
		it('should abort an interaction with an error', async function () {
			const auth = new AuthorizationRequest({
				scope: 'openid'
			});

			const { response: res } = await agent.auth.get({
				query: auth.params
			});

			const url = res.headers.get('location');
			const [, uid] = url.split('/');
			const cookie = res.headers.get('set-cookie');

			const { response } = await agent.ui[uid].abort.get({
				headers: {
					cookie
				}
			});

			expect(response.status).toBe(303);

			return this.agent
				.get(this.url.replace('interaction', 'auth'))
				.expect(303)
				.expect(auth.validateClientLocation)
				.expect(auth.validateState)
				.expect(auth.validateError('access_denied'))
				.expect(auth.validateErrorDescription('End-User aborted interaction'));
		});
	});

	describe('submit login', () => {
		beforeEach(function () {
			const auth = new AuthorizationRequest({
				scope: 'openid'
			});

			return this.agent
				.get('/auth')
				.query(auth)
				.then((response) => {
					this.url = response.headers.location;
				});
		});

		it('accepts the login and resumes auth', async function () {
			let location;
			await this.agent
				.post(`${this.url}`)
				.send({
					prompt: 'login',
					login: 'foobar'
				})
				.type('form')
				.expect(303)
				.expect('location', new RegExp(this.url.replace('interaction', 'auth')))
				.expect(({ headers }) => {
					({ location } = headers);
				});

			await this.agent.get(new URL(location).pathname).expect(303);
		});

		it('checks that the account is a non empty string', async function () {
			let location;
			const spy = sinon.spy();
			this.provider.once('server_error', spy);

			await this.agent
				.post(`${this.url}`)
				.send({
					prompt: 'login',
					login: ''
				})
				.type('form')
				.expect(303)
				.expect('location', new RegExp(this.url.replace('interaction', 'auth')))
				.expect(({ headers }) => {
					({ location } = headers);
				});

			await this.agent.get(new URL(location).pathname).expect(500);

			expect(spy).to.have.property('calledOnce', true);
			const error = spy.firstCall.args[1];
			expect(error).to.be.an.instanceof(TypeError);
			expect(error).to.have.property(
				'message',
				'accountId must be a non-empty string, got: string'
			);
		});
	});

	describe.skip('submit consent', () => {
		beforeEach(function () {
			const cookie = setup.login();
			const auth = new AuthorizationRequest({
				scope: 'openid',
				prompt: 'consent'
			});

			return this.agent
				.get('/auth')
				.query(auth)
				.then((response) => {
					this.url = response.headers.location;
				});
		});

		it('accepts the consent and resumes auth', async function () {
			let location;
			await this.agent
				.post(`${this.url}`)
				.send({
					prompt: 'consent'
				})
				.type('form')
				.expect(303)
				.expect('location', new RegExp(this.url.replace('interaction', 'auth')))
				.expect(({ headers }) => {
					({ location } = headers);
				});

			await this.agent.get(new URL(location).pathname).expect(303);
		});

		it('checks the session interaction came from still exists', async function () {
			let location;
			await this.agent
				.post(`${this.url}`)
				.send({
					prompt: 'consent'
				})
				.type('form')
				.expect(303)
				.expect('location', new RegExp(this.url.replace('interaction', 'auth')))
				.expect(({ headers }) => {
					({ location } = headers);
				});

			const session = this.getSession({ instantiate: true });
			await session.destroy();

			await this.agent
				.get(new URL(location).pathname)
				.expect(400)
				.expect('content-type', 'text/html; charset=utf-8')
				.expect(/interaction session and authentication session mismatch/);
		});

		it('checks the session interaction came from is still the one', async function () {
			let location;
			await this.agent
				.post(`${this.url}`)
				.send({
					prompt: 'consent'
				})
				.type('form')
				.expect(303)
				.expect('location', new RegExp(this.url.replace('interaction', 'auth')))
				.expect(({ headers }) => {
					({ location } = headers);
				});

			await this.login();

			await this.agent
				.get(new URL(location).pathname)
				.expect(400)
				.expect('content-type', 'text/html; charset=utf-8')
				.expect(/interaction session and authentication session mismatch/);
		});

		it('checks the session interaction came from is still the one', async function () {
			let location;
			await this.agent
				.post(`${this.url}`)
				.send({
					prompt: 'consent'
				})
				.type('form')
				.expect(303)
				.expect('location', new RegExp(this.url.replace('interaction', 'auth')))
				.expect(({ headers }) => {
					({ location } = headers);
				});

			await this.login();

			await this.agent
				.get(new URL(location).pathname)
				.expect(400)
				.expect('content-type', 'text/html; charset=utf-8')
				.expect(/interaction session and authentication session mismatch/);
		});
	});
});

describe('resume after consent', () => {
	let setup = null;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url)();
	});
	beforeEach(function () {
		sinon.restore();
	});

	function setupFunc(grant, result, sessionData) {
		const cookies = [];

		let session;
		if (result?.login) {
			session = new Session({ jti: 'sess', ...sessionData });
		} else {
			session = setup.getLastSession();
		}
		const interaction = new provider.Interaction('resume', {
			uid: 'resume',
			params: grant,
			session
		});

		expect(grant).to.be.ok;

		const cookie = `_interaction_resume=resume; path=${this.suitePath('/auth/resume')}; expires=${expire.toGMTString()}; httponly`;
		cookies.push(cookie);

		const sessionCookie = `_session=${session.jti || 'sess'}; path=/; expires=${expire.toGMTString()}; httponly`;
		cookies.push(sessionCookie);

		if (result) {
			if (result.login && !result.login.ts) {
				Object.assign(result.login, { ts: epochTime() });
			}
			Object.assign(interaction, { result });
		}

		this.agent._saveCookies.bind(this.agent)({
			request: { url: this.provider.issuer },
			headers: { 'set-cookie': cookies }
		});

		return Promise.all([
			interaction.save(30), // TODO: bother running the ttl helper?
			session.save(30) // TODO: bother running the ttl helper?
		]);
	}

	describe('general', () => {
		beforeEach(async function () {
			return setup.login();
		});

		it('needs the resume cookie to be present, else renders an err', function () {
			return this.agent
				.get('/auth/resume')
				.expect(400)
				.expect(/authorization request has expired/);
		});

		it('needs to find the session to resume', async function () {
			const auth = new AuthorizationRequest({
				scope: 'openid'
			});

			await setupFunc.call(this, auth);

			sinon.stub(provider.Interaction, 'find').resolves();

			return this.agent
				.get('/auth/resume')
				.expect(400)
				.expect(/interaction session not found/);
		});
	});

	describe('login results', () => {
		it('should process newly established permanent sessions (default)', async function () {
			sinon
				.stub(this.provider.Grant.prototype, 'getOIDCScope')
				.returns('openid');
			const auth = new AuthorizationRequest({
				response_type: 'code',
				response_mode: 'query',
				scope: 'openid'
			});

			await setupFunc.call(this, auth, {
				login: {
					accountId: nanoid()
				}
			});

			return this.agent
				.get('/auth/resume')
				.expect(303)
				.expect('set-cookie', /expires/) // expect a permanent cookie
				.expect(auth.validateClientLocation)
				.expect(auth.validateState)
				.expect(auth.validatePresence(['code', 'state']))
				.expect(() => {
					expect(this.getSession()).to.be.ok.and.not.have.property('transient');
				});
		});

		it('should process newly established permanent sessions (explicit)', async function () {
			sinon.stub(provider.Grant.prototype, 'getOIDCScope').returns('openid');
			const auth = new AuthorizationRequest({
				response_mode: 'query',
				scope: 'openid'
			});

			await setupFunc.call(this, auth, {
				login: {
					accountId: nanoid(),
					remember: true
				}
			});

			return this.agent
				.get('/auth/resume')
				.expect(303)
				.expect('set-cookie', /expires/) // expect a permanent cookie
				.expect(auth.validateClientLocation)
				.expect(auth.validateState)
				.expect(auth.validatePresence(['code', 'state']))
				.expect(() => {
					expect(this.getSession()).to.be.ok.and.not.have.property('transient');
				});
		});

		it('should process newly established temporary sessions', async function () {
			sinon.stub(provider.Grant.prototype, 'getOIDCScope').returns('openid');
			const auth = new AuthorizationRequest({
				response_mode: 'query',
				scope: 'openid'
			});

			await setupFunc.call(this, auth, {
				login: {
					accountId: nanoid(),
					remember: false
				}
			});

			return this.agent
				.get('/auth/resume')
				.expect(303)
				.expect(auth.validateState)
				.expect('set-cookie', /_session=((?!expires).)+/) // expect a transient session cookie
				.expect(auth.validateClientLocation)
				.expect(auth.validatePresence(['code', 'state']))
				.expect(() => {
					expect(this.getSession()).to.be.ok.and.have.property('transient');
				});
		});

		it('should trigger logout when the session subject changes', async function () {
			sinon.stub(provider.Grant.prototype, 'getOIDCScope').returns('openid');
			const auth = new AuthorizationRequest({
				response_mode: 'query',
				scope: 'openid'
			});

			await setupFunc.call(
				this,
				auth,
				{
					login: {
						accountId: nanoid()
					}
				},
				{
					accountId: nanoid()
				}
			);

			let state;

			await this.agent
				.get('/auth/resume')
				.expect(200)
				.expect('content-type', 'text/html; charset=utf-8')
				.expect(
					/document.addEventListener\('DOMContentLoaded', function \(\) { document.forms\[0\].submit\(\) }\);/
				)
				.expect(/<input type="hidden" name="logout" value="yes"\/>/)
				.expect(({ text }) => {
					({ state } = this.getSession());
					expect(state).to.have.property('clientId', 'client');
					expect(state)
						.to.have.property('postLogoutRedirectUri')
						.that.matches(/\/auth\/resume$/);
					expect(text).to.match(
						new RegExp(
							`input type="hidden" name="xsrf" value="${state.secret}"`
						)
					);
				})
				.expect(/<form method="post" action=".+\/session\/end\/confirm">/);

			expect(await this.provider.Interaction.find('resume')).to.be.ok;

			await this.agent
				.post('/session/end/confirm')
				.send({
					xsrf: state.secret,
					logout: 'yes'
				})
				.type('form')
				.expect(303)
				.expect('location', /\/auth\/resume$/);

			await this.agent
				.get('/auth/resume')
				.expect(303)
				.expect(auth.validateClientLocation)
				.expect(auth.validateState);
		});
	});

	describe('custom interaction errors', () => {
		describe('when prompt=none', () => {
			beforeEach(function () {
				return this.login();
			});
			it('custom interactions can fail too (prompt none)', async function () {
				const auth = new AuthorizationRequest({
					scope: 'openid',
					triggerCustomFail: 'foo',
					prompt: 'none'
				});

				return this.agent
					.get('/auth')
					.query(auth)
					.expect(303)
					.expect(auth.validateState)
					.expect(auth.validateClientLocation)
					.expect(auth.validateError('error_foo'))
					.expect(auth.validateErrorDescription('error_description_foo'));
			});
		});

		it('custom interactions can fail too', async function () {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				triggerCustomFail: 'foo'
			});

			await setupFunc.call(this, auth, {
				login: {
					accountId: nanoid(),
					remember: true
				},
				consent: {}
			});

			return this.agent
				.get('/auth/resume')
				.expect(303)
				.expect(auth.validateInteractionRedirect)
				.expect(auth.validateInteraction('login', 'reason_foo'));
		});
	});

	describe('interaction errors', () => {
		it('should abort an interaction when given an error result object (no description)', async function () {
			const auth = new AuthorizationRequest({
				scope: 'openid'
			});

			await setupFunc.call(this, auth, {
				error: 'access_denied'
			});

			return this.agent
				.get('/auth/resume')
				.expect(303)
				.expect(auth.validateState)
				.expect(auth.validatePresence(['error', 'state']))
				.expect(auth.validateError('access_denied'));
		});

		it('should abort an interaction when given an error result object (with state)', async function () {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				state: 'bf458-00aa3'
			});

			await setupFunc.call(this, auth, {
				error: 'access_denied'
			});

			return this.agent
				.get('/auth/resume')
				.expect(303)
				.expect(auth.validateState)
				.expect(auth.validatePresence(['error', 'state']))
				.expect(auth.validateError('access_denied'));
		});

		it('should abort an interaction when given an error result object (with description)', async function () {
			const auth = new AuthorizationRequest({
				scope: 'openid'
			});

			await setupFunc.call(this, auth, {
				error: 'access_denied',
				error_description: 'scope out of reach'
			});

			return this.agent
				.get('/auth/resume')
				.expect(303)
				.expect(auth.validateState)
				.expect(auth.validateError('access_denied'))
				.expect(auth.validateErrorDescription('scope out of reach'));
		});

		it('should abort an interaction when given an error result object (custom error)', async function () {
			const auth = new AuthorizationRequest({
				scope: 'openid'
			});

			await setupFunc.call(this, auth, {
				error: 'custom_foo',
				error_description: 'custom_foobar'
			});

			return this.agent
				.get('/auth/resume')
				.expect(303)
				.expect(auth.validateState)
				.expect(auth.validateError('custom_foo'))
				.expect(auth.validateErrorDescription('custom_foobar'));
		});
	});

	describe('custom requestable prompts', () => {
		beforeEach(function () {
			return this.login();
		});

		it('should fail if they are not resolved', async function () {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				prompt: 'custom'
			});

			await setupFunc.call(this, auth, {});

			return this.agent
				.get('/auth/resume')
				.expect(303)
				.expect(auth.validateInteractionRedirect)
				.expect(auth.validateInteraction('custom', 'custom_prompt'));
		});
	});

	describe('custom unrequestable prompts', () => {
		it('should prompt interaction', async function () {
			const auth = new AuthorizationRequest({
				triggerUnrequestable: 'foo',
				response_mode: 'query',
				scope: 'openid'
			});

			return this.agent
				.get('/auth')
				.query(auth)
				.expect(303)
				.expect(auth.validateInteractionRedirect)
				.expect(auth.validateInteraction('unrequestable', 'un_foo'));
		});

		it('should fail if they are not satisfied', async function () {
			const auth = new AuthorizationRequest({
				triggerUnrequestable: 'foo',
				response_mode: 'query',
				scope: 'openid'
			});

			await setupFunc.call(this, auth, {
				login: {
					accountId: nanoid(),
					remember: true
				},
				consent: {}
			});

			return this.agent
				.get('/auth/resume')
				.expect(303)
				.expect(auth.validateInteractionRedirect)
				.expect(auth.validateInteraction('unrequestable', 'un_foo'));
		});
	});
});
