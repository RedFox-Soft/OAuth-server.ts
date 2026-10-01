import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterEach
} from 'bun:test';

import bootstrap, { agent, getHeader, type Setup } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { errorStore } from 'lib/adapters/index.ts';
import { addons } from 'lib/addon/registry.js';
import { flushForTest, resetQueue } from 'lib/error_store/queue.ts';
import { resetOriginSalt } from 'lib/error_store/redact.ts';

const enabled = ApplicationConfig['errorStore.enabled'];
let setup: Setup;

function faultWhileLoadingTheGrant(message: string) {
	addons.override({
		loadExistingGrant: () => {
			throw new Error(message);
		}
	});
}

async function faultsOn(route: string) {
	await flushForTest();
	return (await errorStore.list({ route })).groups;
}

/**
 * @proves An unexpected fault that ends an authorization request is reported to the client as
 * server_error and is still recorded for the operator, without the redirect carrying a reference.
 */
describe('a fault delivered to the client', () => {
	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
	});

	beforeEach(() => {
		ApplicationConfig['errorStore.enabled'] = true;
		resetQueue();
		resetOriginSalt();
	});

	afterEach(() => {
		ApplicationConfig['errorStore.enabled'] = enabled;
	});

	it('is reported as server_error and recorded when the authorization endpoint faults', async () => {
		const login = await setup.login();
		const auth = new AuthorizationRequest({ scope: 'openid' });
		faultWhileLoadingTheGrant('fault at the authorization endpoint');

		const { response } = await agent.auth.get({
			query: auth.params,
			headers: { cookie: login }
		});

		expect(response.status).toBe(303);
		auth.validateClientLocation(response);
		auth.validateError(response, 'server_error');
		expect(getHeader(response, 'location')).not.toContain('error_reference');

		const [group] = await faultsOn('/auth');
		expect(group).toMatchObject({
			status: 500,
			errorCode: 'server_error',
			surface: 'oauth'
		});
		expect(group.message).toContain('fault at the authorization endpoint');
	});

	it('is reported as server_error and recorded when the server faults while completing sign-in', async () => {
		const login = await setup.login();
		const auth = new AuthorizationRequest({
			scope: 'openid',
			prompt: 'consent'
		});
		const { response: started } = await agent.auth.get({
			query: auth.params,
			headers: { cookie: login }
		});
		const [, , uid] = getHeader(started, 'location').split('/');
		const cookie = [getHeader(started, 'set-cookie'), login].join('; ');
		faultWhileLoadingTheGrant('fault while completing sign-in');

		const { response } = await agent
			.ui({ uid })
			.consent.post({ action: 'allow' }, { headers: { cookie } });

		expect(response.status).toBe(303);
		auth.validateClientLocation(response);
		auth.validateError(response, 'server_error');
		auth.validateState(response);
		expect(getHeader(response, 'location')).not.toContain('error_reference');

		const [group] = await faultsOn('/ui/:uid/consent');
		expect(group).toMatchObject({
			status: 500,
			errorCode: 'server_error',
			surface: 'interaction'
		});
		expect(group.message).toContain('fault while completing sign-in');
	});
});
