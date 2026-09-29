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
import { importJWK } from 'jose';

import { adapter } from 'lib/adapters/index.ts';
import nanoid from '../../lib/helpers/nanoid.ts';
import * as JWT from '../../lib/helpers/jwt.ts';
import bootstrap, { agent } from '../test_helper.js';
import { ISSUER } from 'lib/configs/env.js';
import { Client, clientKeys } from 'lib/models/client.js';

/*
 * A client assertion's `jti` is single use under concurrency, not only in sequence. Replay detection
 * looked the identifier up and then stored it, so the same captured assertion presented by several
 * requests at once found it unseen in every one of them and authenticated each.
 */

/**
 * @proves A client assertion presented by several requests at once authenticates exactly one of
 * them.
 */
describe('a client assertion presented concurrently', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'client_auth' });
	});

	/*
	 * The in-memory store answers a lookup within the same turn of the event loop, so the window a real
	 * datastore opens between reading and answering never opens here. An answer that takes as long to
	 * arrive as a round-trip does is what lets the requests overlap as they would in production; the
	 * verdict is still the adapter's.
	 */
	beforeEach(() => {
		const store = adapter('ReplayDetection');
		const find = store.find.bind(store);
		spyOn(store, 'find').mockImplementation(async (id: string) => {
			const found = await find(id);
			await Bun.sleep(5);
			return found;
		});
	});

	afterEach(() => {
		mock.restore();
	});

	it('authenticates exactly one of the requests', async () => {
		const key = await importJWK(
			clientKeys(
				await Client.find('client-jwt-secret')
			).symmetric.selectForSign({ alg: 'HS256' })[0]
		);
		const assertion = await JWT.sign(
			{
				jti: nanoid(),
				aud: ISSUER,
				sub: 'client-jwt-secret',
				iss: 'client-jwt-secret'
			},
			key,
			'HS256',
			{ expiresIn: 60 }
		);

		const results = await Promise.all(
			Array.from({ length: 5 }, () =>
				agent.token.post({
					client_assertion: assertion,
					grant_type: 'client_credentials',
					client_assertion_type:
						'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
				})
			)
		);

		expect(results.filter(({ status }) => status === 200)).toHaveLength(1);
	});
});
