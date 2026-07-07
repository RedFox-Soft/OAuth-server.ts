import {
	describe,
	it,
	beforeAll,
	beforeEach,
	afterEach,
	expect,
	mock,
	spyOn
} from 'bun:test';
import timekeeper from 'timekeeper';

import bootstrap, {
	agent,
	jsonToFormUrlEncoded,
	passInteractionChecks
} from '../test_helper.js';
import { provider } from 'lib/provider.js';
import { DeviceCode } from 'lib/models/device_code.js';
import { Client } from 'lib/models/client.js';

const route = 'device';
const form = 'application/x-www-form-urlencoded';

describe('GET code_verification endpoint', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url)();
	});

	describe('when accessed without user_code in query (verification_uri)', () => {
		it('renders 200 OK end-user form with csrf', async () => {
			const { status, data, response } = await agent[route].get();
			expect(status).toBe(200);
			expect(response.headers.get('content-type')).toBe(
				'text/html; charset=utf-8'
			);
			expect(data).toContain('id="op.deviceInputForm"');
			expect(data).toMatch(/name="xsrf" value="[0-9a-f]+"/);
		});
	});

	describe('when accessed with user_code in query (verification_uri_complete)', () => {
		it('renders 200 OK self-submitting form with csrf and the value from uri', async () => {
			const { status, data } = await agent[route].get({
				query: { user_code: '123-456-789' }
			});
			expect(status).toBe(200);
			expect(data).toContain('document.forms[0].submit();');
			expect(data).toMatch(/name="xsrf" value="[0-9a-f]+"/);
			expect(data).toContain('method="post"');
			expect(data).toContain('/device"');
			expect(data).toContain('name="user_code" value="123-456-789"');
		});

		it('escapes the user_code values', async () => {
			const { data } = await agent[route].get({
				query: { user_code: '&<>"\'123-456-789' }
			});
			expect(data).toContain(
				'name="user_code" value="&amp;&lt;&gt;&quot;&#x27;123-456-789"'
			);
		});
	});
});

describe('POST code_verification endpoint w/o verification', () => {
	let setup = null;
	const xsrf = 'foo';

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url)();
		await setup.login();
	});

	beforeEach(() => {
		setup.getSession().state = { secret: xsrf };
	});

	afterEach(() => {
		timekeeper.reset();
		mock.restore();
		provider.removeAllListeners('code_verification.error');
	});

	function post(body) {
		return agent[route].post(jsonToFormUrlEncoded(body), {
			headers: {
				'content-type': form,
				cookie: `_session=${setup.getSessionId()}`
			}
		});
	}

	it('renders a confirmation page', async () => {
		await new DeviceCode({
			clientId: 'client',
			userCode: 'FOOCODE',
			deviceInfo: { ip: '127.0.0.1', ua: 'foo' }
		}).save();

		const { status, data } = await post({ xsrf, user_code: 'FOO-CODE' });
		expect(status).toBe(200);
		expect(data).toContain('id="op.deviceConfirmForm"');
	});

	it('re-renders on no submitted code', async () => {
		const errSpy = mock();
		provider.once('code_verification.error', errSpy);

		const { status, data } = await post({ xsrf });
		expect(status).toBe(200);
		expect(data).toContain('id="op.deviceInputForm"');
		expect(data).toContain(
			'<p class="red">The code you entered is incorrect. Try again</p>'
		);
		expect(errSpy).not.toHaveBeenCalled();
	});

	it('re-renders on not found code', async () => {
		const errSpy = mock();
		provider.once('code_verification.error', errSpy);

		const { status, data } = await post({ xsrf, user_code: 'FOO-NOT-FOUND' });
		expect(status).toBe(200);
		expect(data).toContain('id="op.deviceInputForm"');
		expect(data).toContain(
			'<p class="red">The code you entered is incorrect. Try again</p>'
		);
		expect(errSpy).not.toHaveBeenCalled();
	});

	it('re-renders on found but expired code', async () => {
		const errSpy = mock();
		provider.once('code_verification.error', errSpy);
		await new DeviceCode({ clientId: 'client', userCode: 'FOOEXPIRED' }).save();

		timekeeper.travel(Date.now() + (10 * 60 + 10) * 1000);
		const { status, data } = await post({ xsrf, user_code: 'FOO-EXPIRED' });
		expect(status).toBe(200);
		expect(data).toContain('id="op.deviceInputForm"');
		expect(data).toContain(
			'<p class="red">The code you entered is incorrect. Try again</p>'
		);
		expect(errSpy).not.toHaveBeenCalled();
	});

	it('re-renders on found but already used code', async () => {
		const errSpy = mock();
		provider.once('code_verification.error', errSpy);
		await new DeviceCode({
			clientId: 'client',
			userCode: 'FOOCONSUMED',
			accountId: 'account'
		}).save();

		const { status, data } = await post({ xsrf, user_code: 'FOO-CONSUMED' });
		expect(status).toBe(200);
		expect(data).toContain('id="op.deviceInputForm"');
		expect(data).toContain(
			'<p class="red">The code you entered is incorrect. Try again</p>'
		);
		expect(errSpy).not.toHaveBeenCalled();
	});

	it('re-renders on invalid client', async () => {
		const errSpy = mock();
		provider.once('code_verification.error', errSpy);
		await new DeviceCode({
			userCode: 'FOONOTFOUNDCLIENT',
			clientId: 'client'
		}).save();

		spyOn(Client, 'find').mockResolvedValue(undefined);

		const { error } = await post({
			xsrf,
			user_code: 'FOO-NOT-FOUND-CLIENT'
		});
		expect(error.status).toBe(400);
		expect(error.value).toContain('id="op.deviceInputForm"');
		expect(error.value).toContain(
			'<p class="red">There was an error processing your request</p>'
		);
		expect(errSpy).toHaveBeenCalledTimes(1);
	});

	it('re-renders on missing session state', async () => {
		const errSpy = mock();
		provider.once('code_verification.error', errSpy);
		await new DeviceCode({ clientId: 'client', userCode: 'FOOCSRF1' }).save();

		delete setup.getSession().state;
		const { error } = await post({ xsrf, user_code: 'FOO-CSRF-1' });
		expect(error.status).toBe(400);
		expect(error.value).toContain('id="op.deviceInputForm"');
		expect(error.value).toContain(
			'<p class="red">There was an error processing your request</p>'
		);
		expect(errSpy).toHaveBeenCalledTimes(1);
	});

	it('re-renders on invalid csrf', async () => {
		const errSpy = mock();
		provider.once('code_verification.error', errSpy);
		await new DeviceCode({ clientId: 'client', userCode: 'FOOCSRF2' }).save();

		const { error } = await post({
			xsrf: 'invalid-csrf',
			user_code: 'FOO-CSRF-FOO'
		});
		expect(error.status).toBe(400);
		expect(error.value).toContain('id="op.deviceInputForm"');
		expect(error.value).toContain(
			'<p class="red">There was an error processing your request</p>'
		);
		expect(errSpy).toHaveBeenCalledTimes(1);
	});
});

describe('POST code_verification endpoint w/ verification', () => {
	let setup = null;
	const xsrf = 'foo';

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url)();
		await setup.login({
			scope: 'openid email',
			rejectedClaims: ['email_verified']
		});
	});

	beforeEach(() => {
		setup.getSession().state = { secret: xsrf };
	});

	afterEach(() => {
		timekeeper.reset();
		mock.restore();
	});

	function post(body) {
		return agent[route].post(jsonToFormUrlEncoded(body), {
			headers: {
				'content-type': form,
				cookie: `_session=${setup.getSessionId()}`
			}
		});
	}

	passInteractionChecks('native_client_prompt', 'op_claims_missing', () => {
		it('accepts an abort command', async () => {
			let code = await new DeviceCode({
				clientId: 'client',
				userCode: 'FOO',
				params: {
					scope: 'openid email',
					client_id: 'client',
					claims: { userinfo: { email: null } }
				}
			}).save();

			const { status, data } = await post({
				xsrf,
				confirm: '',
				abort: 'yes',
				user_code: 'FOO'
			});
			expect(status).toBe(200);
			expect(data).toMatch(/The Sign-in request was interrupted/);

			code = await DeviceCode.find(code);
			expect(code.payload).not.toHaveProperty('accountId');
			expect(code.payload).toHaveProperty('error', 'access_denied');
			expect(code.payload).toHaveProperty(
				'errorDescription',
				'End-User aborted interaction'
			);
		});

		it('renders a confirmation and assigns', async () => {
			let code = await new DeviceCode({
				clientId: 'client',
				userCode: 'FOO',
				params: {
					scope: 'openid email',
					client_id: 'client',
					claims: { userinfo: { email: null } }
				}
			}).save();

			const { status } = await post({ xsrf, confirm: 'yes', user_code: 'FOO' });
			expect(status).toBe(200);

			code = await DeviceCode.find(code);
			const session = setup.getSession();

			expect(code.payload).not.toHaveProperty('sid');
			expect(code.payload).toHaveProperty('accountId', session.accountId);
			expect(code.payload).toHaveProperty('authTime', session.loginTs);
			expect(code.payload).toHaveProperty('scope', 'openid email');
			expect(code.payload.claims).toEqual({ userinfo: { email: null } });
		});

		it('renders a confirmation and assigns (incl. sid because of client configuration)', async () => {
			let code = await new DeviceCode({
				clientId: 'client-backchannel',
				userCode: 'FOO',
				params: {
					scope: 'openid',
					client_id: 'client-backchannel'
				}
			}).save();

			const { status } = await post({ xsrf, confirm: 'yes', user_code: 'FOO' });
			expect(status).toBe(200);

			code = await DeviceCode.find(code);
			expect(code.payload).toHaveProperty('sid');
		});

		it('renders a confirmation and assigns (incl. sid because of claims)', async () => {
			let code = await new DeviceCode({
				clientId: 'client',
				userCode: 'FOO',
				params: {
					scope: 'openid',
					client_id: 'client',
					claims: { id_token: { sid: null } }
				}
			}).save();

			const { status } = await post({ xsrf, confirm: 'yes', user_code: 'FOO' });
			expect(status).toBe(200);

			code = await DeviceCode.find(code);
			expect(code.payload).toHaveProperty('sid');
		});

		it('allows for punctuation to be included and characters to be downcased', async () => {
			let code = await new DeviceCode({
				clientId: 'client',
				userCode: 'FOOBAR',
				params: {
					scope: 'openid email',
					client_id: 'client',
					claims: { userinfo: { email: null } }
				}
			}).save();

			const { status } = await post({
				xsrf,
				confirm: 'yes',
				user_code: 'f o o b a r'
			});
			expect(status).toBe(200);

			code = await DeviceCode.find(code);
			const session = setup.getSession();

			expect(code.payload).toHaveProperty('accountId', session.accountId);
			expect(code.payload).toHaveProperty('authTime', session.loginTs);
			expect(code.payload).toHaveProperty('scope', 'openid email');
			expect(code.payload.claims).toEqual({ userinfo: { email: null } });
		});
	});
});
