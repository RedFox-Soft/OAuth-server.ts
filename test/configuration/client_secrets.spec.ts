import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import { needsSecret } from 'lib/models/client.js';

/**
 * @proves A client registered for a secret-based authentication method cannot exist without a
 * secret.
 */
describe('Client#add', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'client_secrets' });
	});

	it('client secret is mandatory if client auth needs it', () => {
		expect(
			needsSecret({
				token_endpoint_auth_method: 'client_secret_basic'
			})
		).toBe(true);
	});
});
