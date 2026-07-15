import {
	describe,
	it,
	beforeAll,
	afterEach,
	beforeEach,
	expect,
	spyOn,
	mock
} from 'bun:test';
import nanoid from '../../lib/helpers/nanoid.ts';
import bootstrap, { agent } from '../test_helper.js';
import epochTime from '../../lib/helpers/epoch_time.ts';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { provider } from 'lib/index.js';
import { Session } from 'lib/models/session.js';
import { ISSUER } from 'lib/configs/env.js';
import { Interaction } from 'lib/models/interaction.js';
import { Grant } from 'lib/models/grant.js';
import { getUserStore } from 'lib/adapters/index.js';

const expire = new Date();
expire.setDate(expire.getDate() + 1);

describe('devInteractions', async () => {
	const setup = await bootstrap(import.meta.url);
	afterEach(function () {
		mock.restore();
	});

	describe('render login', () => {
		const object = {};

		beforeEach(async function () {
			const auth = new AuthorizationRequest({
				scope: 'openid'
			});
			const { response } = await agent.auth.get({
				query: auth.params
			});

			const url = response.headers.get('location');
			const [, , uid] = url.split('/');

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
			spyOn(Interaction, 'find').mockResolvedValue(undefined);

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

	describe('render interaction', () => {
		let uid = null;
		let cookie = null;
		let url = null;

		beforeEach(async function () {
			const login = await setup.login();
			const auth = new AuthorizationRequest({
				scope: 'openid',
				prompt: 'consent'
			});

			const { response } = await agent.auth.get({
				query: auth.params,
				headers: {
					cookie: login
				}
			});
			cookie = [response.headers.get('set-cookie'), login];
			url = response.headers.get('location');
			[, , uid] = url.split('/');
		});

		it('with a form', async function () {
			const { data, status } = await agent.ui[uid].consent.get({
				headers: {
					cookie
				}
			});
			expect(status).toBe(200);
			expect(data).toContain('method="post"');
			expect(data).toContain('Consent Required');
		});

		it('checks that the authentication session is still there', async function () {
			const session = setup.getLastSession();
			await session.destroy();

			const { error } = await agent.ui[uid].consent.get({
				headers: {
					cookie
				}
			});
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description: 'session not found'
			});
		});

		it("checks that the authentication session's principal didn't change", async function () {
			const session = setup.getLastSession();
			session.payload.accountId = 'foobar';
			await session.save();

			const { error } = await agent.ui[uid].consent.get({
				headers: {
					cookie
				}
			});
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description: 'session principal changed'
			});
		});
	});

	describe('navigate to abort', () => {
		it('rejects the request with access_denied when the End-User cancels consent', async function () {
			const login = await setup.login();
			const auth = new AuthorizationRequest({
				scope: 'openid',
				prompt: 'consent'
			});

			const { response: res } = await agent.auth.get({
				query: auth.params,
				headers: {
					cookie: login
				}
			});

			const url = res.headers.get('location');
			const [, , uid] = url.split('/');
			const cookie = [res.headers.get('set-cookie'), login];

			const { response: aborted, error } = await agent.ui[uid].consent.post(
				{
					action: 'cancel'
				},
				{
					headers: {
						cookie
					}
				}
			);

			expect(aborted.status).toBe(400);
			expect(error.value).toEqual({
				error: 'access_denied',
				error_description: 'End-User denied consent'
			});
		});
	});

	describe('submit login', () => {
		let uid = null;
		let cookie = null;

		beforeEach(async function () {
			const auth = new AuthorizationRequest({
				scope: 'openid'
			});
			const { response } = await agent.auth.get({
				query: auth.params
			});
			const url = response.headers.get('location');
			[, , uid] = url.split('/');
			cookie = response.headers.get('set-cookie');
		});

		it('accepts valid credentials and resumes the authorization request', async function () {
			const password = 'sup3rsecret';
			const username = `${nanoid()}@example.com`;
			await getUserStore().create(username, await Bun.password.hash(password));

			const { response } = await agent.ui[uid].login.post(
				{
					username,
					password
				},
				{
					headers: {
						cookie
					}
				}
			);

			// A successful login leaves the interaction and hands the flow back to the
			// authorization pipeline (a redirect), rather than re-rendering the login form.
			expect(response.status).toBe(303);
			expect(response.headers.get('location')).toBeTruthy();
		});

		it('re-renders the login form with an error for an unknown user', async function () {
			const { error } = await agent.ui[uid].login.post(
				{
					username: `${nanoid()}@example.com`,
					password: 'whatever'
				},
				{
					headers: {
						cookie
					}
				}
			);

			expect(error.status).toBe(400);
			expect(error.value).toContain('Invalid username or password');
		});

		it('re-renders the login form with an error for a wrong password', async function () {
			const username = `${nanoid()}@example.com`;
			await getUserStore().create(
				username,
				await Bun.password.hash('the-real-password')
			);

			const { error } = await agent.ui[uid].login.post(
				{
					username,
					password: 'wrong-password'
				},
				{
					headers: {
						cookie
					}
				}
			);

			expect(error.status).toBe(400);
			expect(error.value).toContain('Invalid username or password');
		});
	});

	describe('submit consent', () => {
		let uid = null;
		let cookie = null;

		beforeEach(async function () {
			const login = await setup.login();
			const auth = new AuthorizationRequest({
				scope: 'openid',
				prompt: 'consent'
			});

			const { response } = await agent.auth.get({
				query: auth.params,
				headers: {
					cookie: login
				}
			});
			cookie = [response.headers.get('set-cookie'), ...login].join('; ');
			const url = response.headers.get('location');
			[, , uid] = url.split('/');
		});

		it('accepts the consent and resumes the authorization request', async function () {
			const { response } = await agent.ui[uid].consent.post(
				{
					action: 'allow'
				},
				{
					headers: {
						cookie
					}
				}
			);

			expect(response.status).toBe(303);
			expect(response.headers.get('location')).toBeTruthy();
		});

		it('checks that the authentication session is still there', async function () {
			const session = setup.getLastSession();
			await session.destroy();

			const { error } = await agent.ui[uid].consent.post(
				{
					action: 'allow'
				},
				{
					headers: {
						cookie
					}
				}
			);
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description: 'session not found'
			});
		});

		it("checks that the authentication session's principal didn't change", async function () {
			const session = setup.getLastSession();
			session.payload.accountId = 'foobar';
			await session.save();

			const { error } = await agent.ui[uid].consent.post(
				{
					action: 'allow'
				},
				{
					headers: {
						cookie
					}
				}
			);
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description: 'session principal changed'
			});
		});
	});
});

describe('resume after consent', async () => {
	const setup = await bootstrap(import.meta.url);
	afterEach(function () {
		mock.restore();
	});

	// Persists a `resume` interaction the way the authorization pipeline would have, then returns the
	// matching `_interaction` cookie. The web resume flow is GET /ui/:uid/resume (uid === 'resume');
	// the interaction carries the stored authorization `params` plus the interaction `result`.
	async function saveResume(params, result) {
		const sess = new Interaction('resume', {
			uid: 'resume',
			cookieID: 'cookieID'
		});
		if (params) {
			// clone: the resume pipeline mutates the stored params (e.g. defaulting `resource`),
			// and we must not let that leak back into the AuthorizationRequest's own `params`.
			Object.assign(sess.payload, { params: { ...params } });
		}
		if (result) {
			if (result.login && !result.login.ts) {
				Object.assign(result.login, { ts: epochTime() });
			}
			Object.assign(sess.payload, { result });
		}
		await sess.save(30);
		return `_interaction=cookieID; path=/ui/resume/resume; expires=${expire.toGMTString()}; httponly`;
	}

	describe('general', () => {
		it('needs the resume cookie to be present, else renders an err', async function () {
			const { error } = await agent.ui['resume'].resume.get();

			expect(error.status).toBe(422);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description: 'Invalid interaction cookie'
			});
		});

		it('needs to find the session to resume', async function () {
			const session = await setup.login();
			const auth = new AuthorizationRequest({
				scope: 'openid'
			});

			const cookie = await saveResume(auth.params);

			spyOn(Interaction, 'find').mockResolvedValue(undefined);

			const { error } = await agent.ui['resume'].resume.get({
				headers: {
					cookie: [...session, cookie].join('; ')
				}
			});

			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description: 'interaction session not found'
			});
		});
	});

	describe('login results', () => {
		it('should process a login result and resume to the client with a code', async function () {
			const session = await setup.login();
			const auth = new AuthorizationRequest({
				response_type: 'code',
				response_mode: 'query',
				scope: 'openid'
			});

			const cookie = await saveResume(auth.params, {
				login: {
					accountId: setup.getAccountId()
				}
			});

			const { response } = await agent.ui['resume'].resume.get({
				headers: {
					cookie: [...session, cookie].join('; ')
				}
			});

			expect(response.status).toBe(303);
			auth.validateClientLocation(response);
			auth.validateState(response);
			auth.validatePresence(response, ['code', 'state']);
		});

		it('should process an explicitly permanent (remember) login result', async function () {
			const session = await setup.login();
			const auth = new AuthorizationRequest({
				response_mode: 'query',
				scope: 'openid'
			});

			const cookie = await saveResume(auth.params, {
				login: {
					accountId: setup.getAccountId(),
					remember: true
				}
			});

			const { response } = await agent.ui['resume'].resume.get({
				headers: {
					cookie: [...session, cookie].join('; ')
				}
			});

			expect(response.status).toBe(303);
			auth.validateClientLocation(response);
			auth.validateState(response);
			auth.validatePresence(response, ['code', 'state']);
		});

		it('should process a transient (remember: false) login result', async function () {
			const session = await setup.login();
			const auth = new AuthorizationRequest({
				response_mode: 'query',
				scope: 'openid'
			});

			const cookie = await saveResume(auth.params, {
				login: {
					accountId: setup.getAccountId(),
					remember: false
				}
			});

			const { response } = await agent.ui['resume'].resume.get({
				headers: {
					cookie: [...session, cookie].join('; ')
				}
			});

			expect(response.status).toBe(303);
			auth.validateClientLocation(response);
			auth.validateState(response);
			auth.validatePresence(response, ['code', 'state']);
		});

		it('should trigger logout when the session subject changes', async function () {
			const session = await setup.login();
			const auth = new AuthorizationRequest({
				response_mode: 'query',
				scope: 'openid'
			});

			// the authenticated session belongs to a different subject than the login result
			const cookie = await saveResume(auth.params, {
				login: {
					accountId: nanoid()
				}
			});

			const { response, data } = await agent.ui['resume'].resume.get({
				headers: {
					cookie: [...session, cookie].join('; ')
				}
			});

			expect(response.status).toBe(200);
			expect(response.headers.get('content-type')).toContain('text/html');
			expect(data).toContain('name="logout"');
			expect(data).toContain('/logout/confirm');
		});
	});

	describe('custom interaction errors', () => {
		it('custom interactions can fail too', async function () {
			const session = await setup.login();
			const auth = new AuthorizationRequest({
				scope: 'openid',
				triggerCustomFail: 'foo'
			});

			const cookie = await saveResume(auth.params, {
				login: {
					accountId: setup.getAccountId(),
					remember: true
				},
				consent: {}
			});

			const { response } = await agent.ui['resume'].resume.get({
				headers: {
					cookie: [...session, cookie].join('; ')
				}
			});

			expect(response.status).toBe(303);
			auth.validateInteractionRedirect(response);
			auth.validateInteraction(response, 'login', 'reason_foo');
		});
	});

	describe('interaction errors', () => {
		it('should abort an interaction when given an error result object (no description)', async function () {
			const session = await setup.login();
			const auth = new AuthorizationRequest({
				scope: 'openid'
			});

			const cookie = await saveResume(auth.params, {
				error: 'access_denied'
			});

			const { response } = await agent.ui['resume'].resume.get({
				headers: {
					cookie: [...session, cookie].join('; ')
				}
			});

			expect(response.status).toBe(303);
			auth.validateState(response);
			auth.validatePresence(response, ['error', 'state']);
			auth.validateError(response, 'access_denied');
		});

		it('should abort an interaction when given an error result object (with state)', async function () {
			const session = await setup.login();
			const auth = new AuthorizationRequest({
				scope: 'openid',
				state: 'bf458-00aa3'
			});

			const cookie = await saveResume(auth.params, {
				error: 'access_denied'
			});

			const { response } = await agent.ui['resume'].resume.get({
				headers: {
					cookie: [...session, cookie].join('; ')
				}
			});

			expect(response.status).toBe(303);
			auth.validateState(response);
			auth.validatePresence(response, ['error', 'state']);
			auth.validateError(response, 'access_denied');
		});

		it('should abort an interaction when given an error result object (with description)', async function () {
			const session = await setup.login();
			const auth = new AuthorizationRequest({
				scope: 'openid'
			});

			const cookie = await saveResume(auth.params, {
				error: 'access_denied',
				error_description: 'scope out of reach'
			});

			const { response } = await agent.ui['resume'].resume.get({
				headers: {
					cookie: [...session, cookie].join('; ')
				}
			});

			expect(response.status).toBe(303);
			auth.validateState(response);
			auth.validateError(response, 'access_denied');
			auth.validateErrorDescription(response, 'scope out of reach');
		});

		it('should abort an interaction when given an error result object (custom error)', async function () {
			const session = await setup.login();
			const auth = new AuthorizationRequest({
				scope: 'openid'
			});

			const cookie = await saveResume(auth.params, {
				error: 'custom_foo',
				error_description: 'custom_foobar'
			});

			const { response } = await agent.ui['resume'].resume.get({
				headers: {
					cookie: [...session, cookie].join('; ')
				}
			});

			expect(response.status).toBe(303);
			auth.validateState(response);
			auth.validateError(response, 'custom_foo');
			auth.validateErrorDescription(response, 'custom_foobar');
		});
	});

	describe('custom requestable prompts', () => {
		it('should fail if they are not resolved', async function () {
			const session = await setup.login();
			const auth = new AuthorizationRequest({
				scope: 'openid',
				prompt: 'custom'
			});

			const cookie = await saveResume(auth.params, {});

			const { response } = await agent.ui['resume'].resume.get({
				headers: {
					cookie: [...session, cookie].join('; ')
				}
			});

			expect(response.status).toBe(303);
			auth.validateInteractionRedirect(response);
			auth.validateInteraction(response, 'custom', 'custom_prompt');
		});
	});

	describe('custom unrequestable prompts', () => {
		it('should fail if they are not satisfied', async function () {
			const session = await setup.login();
			const auth = new AuthorizationRequest({
				triggerUnrequestable: 'foo',
				response_mode: 'query',
				scope: 'openid'
			});

			const cookie = await saveResume(auth.params, {
				login: {
					accountId: setup.getAccountId(),
					remember: true
				},
				consent: {}
			});

			const { response } = await agent.ui['resume'].resume.get({
				headers: {
					cookie: [...session, cookie].join('; ')
				}
			});

			expect(response.status).toBe(303);
			auth.validateInteractionRedirect(response);
			auth.validateInteraction(response, 'unrequestable', 'un_foo');
		});
	});
});
