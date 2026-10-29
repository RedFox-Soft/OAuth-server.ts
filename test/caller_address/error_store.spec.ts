import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap, { agent, type Setup } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { errorStore } from 'lib/adapters/index.ts';
import { addons } from 'lib/addon/registry.js';
import { flushForTest, resetQueue } from 'lib/error_store/queue.ts';
import { PEER_HEADER, statePeerThroughHeader } from './helper.js';

const CALLER = '203.0.113.7';

let setup: Setup;

beforeAll(async () => {
	setup = await bootstrap(import.meta.url);
});

/**
 * @proves A fault record names the caller the server attributed the request to, not an address
 * the caller wrote into a forwarded header.
 */
describe('the address a fault record keeps', () => {
	beforeEach(() => {
		ApplicationConfig['clientAddress.source'] = 'automatic';
		resetQueue();
		statePeerThroughHeader();
	});

	it('is the attributed caller, not a forged entry, behind a private proxy', async () => {
		const login = await setup.login();
		const auth = new AuthorizationRequest({ scope: 'openid' });
		addons.override({
			loadExistingGrant: () => {
				throw new Error('fault while the caller is known');
			}
		});

		await agent.auth.get({
			query: auth.params,
			headers: {
				cookie: login,
				[PEER_HEADER]: '10.0.0.2',
				'x-forwarded-for': `192.0.2.66, ${CALLER}`
			}
		});

		await flushForTest();
		const [group] = (await errorStore.list({ route: '/auth' })).groups;
		expect(group.samples.map((sample) => sample.origin)).toEqual([CALLER]);
	});
});
