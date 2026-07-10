import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import { provider } from 'lib/provider.js';
import { Client } from 'lib/models/client.js';

describe('Client#add', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'client_secrets' })();
	});

	it('client secret is mandatory if client auth needs it', () => {
		expect(
			Client.needsSecret({
				token_endpoint_auth_method: 'client_secret_basic'
			})
		).toBe(true);
	});
});
