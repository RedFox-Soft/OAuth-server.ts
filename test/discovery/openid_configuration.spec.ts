import i from 'lib/helpers/weak_cache.js';
import { describe, it, beforeAll, afterEach, expect, mock } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { provider } from 'lib/provider.js';

const discoveryEndpoint = agent['.well-known']['openid-configuration'];

describe('/.well-known/openid-configuration', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('responds with json 200', async () => {
		const { status, response } = await discoveryEndpoint.get();

		expect(status).toBe(200);
		expect(response.headers.get('content-type')).toMatch(/application\/json/);
	});

	it('is configurable with extra properties', async () => {
		i(provider).configuration.discovery.service_documentation =
			'https://docs.example.com';
		i(provider).configuration.discovery.authorization_endpoint =
			'this will not be used';

		const { data } = await discoveryEndpoint.get();
		if (!data) throw new Error('expected response data');

		expect(data).toHaveProperty(
			'service_documentation',
			'https://docs.example.com'
		);
		expect(data.authorization_endpoint).not.toBe('this will not be used');
	});

	describe('with unexpected exceptions', () => {
		afterEach(() => mock.restore());

		it('handles exceptions with json 500 and emits server_error', async () => {
			const spy = mock();
			provider.once('server_error', spy);

			// Force the discovery handler to throw while it applies discovery overrides.
			// bun's spyOn can't stub an accessor, so override the getter directly and
			// restore the original descriptor afterwards.
			const config = i(provider).configuration;
			const original = Object.getOwnPropertyDescriptor(config, 'discovery');
			Object.defineProperty(config, 'discovery', {
				configurable: true,
				get() {
					throw new Error('oops! something went wrong');
				}
			});

			try {
				const { error } = await discoveryEndpoint.get();
				if (!error) throw new Error('expected error response');

				expect(error.status).toBe(500);
				expect(error.value).toEqual({
					error: 'server_error',
					error_description: 'An unexpected error occurred'
				});
				expect(spy).toHaveBeenCalledTimes(1);
			} finally {
				if (original) {
					Object.defineProperty(config, 'discovery', original);
				} else {
					delete config.discovery;
				}
			}
		});
	});
});
