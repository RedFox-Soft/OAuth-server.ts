import {
	afterEach,
	beforeAll,
	describe,
	expect,
	it,
	mock,
	setSystemTime
} from 'bun:test';

import bootstrap, {
	agent,
	DEFAULT_SESSION_COOKIE,
	formAgent,
	seedAccount,
	type Setup
} from '../test_helper.js';
import { eventBus, type ServerListener } from 'lib/event_bus.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';

type Saved = { payload: Record<string, unknown> };

/* The next access token the server saves, as it saves it. */
function nextAccessToken(): () => Saved {
	const spy = mock<ServerListener<'access_token.saved'>>();
	eventBus.once('access_token.saved', spy);
	return () => spy.mock.calls[0][0];
}

/**
 * @proves An access token issued after a person's interactive sign-in says when and how they signed in, and a refresh
 * keeps the original sign-in rather than presenting itself as a new one — what a check at the proxy tells a person's
 * token from a machine's by (specs/124 FR-019).
 */
describe('the sign-in an access token carries', () => {
	let setup: Setup;
	let cookie: string;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'resource_indicators' });
		seedAccount('accountId');
		cookie = await setup.login({
			resources: { 'urn:wl:explicit': 'api:read api:write' }
		});
	});

	afterEach(() => {
		setSystemTime();
	});

	it('is the sign-in time after an authorization code, and the same time after a refresh', async () => {
		const codeSaved = mock<ServerListener<'authorization_code.saved'>>();
		eventBus.once('authorization_code.saved', codeSaved);
		const auth = new AuthorizationRequest({
			resource: ['urn:wl:explicit'],
			scope: 'api:read'
		});
		await agent.auth.get({ query: auth.params, headers: { cookie } });
		const code = codeSaved.mock.calls[0][0];
		const refreshSaved = mock<ServerListener<'refresh_token.saved'>>();
		eventBus.once('refresh_token.saved', refreshSaved);
		const issued = nextAccessToken();

		await agent.token.post({
			client_id: 'client',
			grant_type: 'authorization_code',
			code_verifier: auth.code_verifier,
			code: code.jti
		});
		const first = issued().payload;
		setSystemTime(Date.now() + 3_600_000);
		const refreshed = nextAccessToken();
		await agent.token.post({
			client_id: 'client',
			grant_type: 'refresh_token',
			refresh_token: refreshSaved.mock.calls[0][0].jti
		});
		const second = refreshed().payload;

		expect(typeof first.authTime).toBe('number');
		expect(first.authTime).toBe(code.payload.authTime);
		expect(second.authTime).toBe(first.authTime);
	});

	it('is the sign-in time after a device authorization', async () => {
		const started = await formAgent.device.auth.post({
			client_id: 'client',
			resource: ['urn:wl:explicit'],
			scope: 'api:read'
		});
		if (!started.data?.user_code || !started.data.device_code) {
			throw new Error('expected a device authorization');
		}
		setup.getSession().state = { secret: 'foo' };
		await formAgent.device.post(
			{ user_code: started.data.user_code, xsrf: 'foo', confirm: 'true' },
			{
				headers: { cookie: `${DEFAULT_SESSION_COOKIE}=${setup.getSessionId()}` }
			}
		);
		const issued = nextAccessToken();

		await agent.token.post({
			client_id: 'client',
			grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
			device_code: started.data.device_code
		});

		expect(typeof issued().payload.authTime).toBe('number');
	});
});
