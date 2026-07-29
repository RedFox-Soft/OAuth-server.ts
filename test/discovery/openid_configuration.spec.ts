import { describe, it, beforeAll, afterEach, expect, mock } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { eventBus } from 'lib/event_bus.js';
import { ApplicationConfig } from 'lib/configs/application.js';

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
		const original = { ...ApplicationConfig.discovery };
		ApplicationConfig.discovery.service_documentation =
			'https://docs.example.com';
		ApplicationConfig.discovery.authorization_endpoint =
			'this will not be used';

		try {
			const { data } = await discoveryEndpoint.get();
			if (!data) throw new Error('expected response data');

			expect(data).toHaveProperty(
				'service_documentation',
				'https://docs.example.com'
			);
			expect(data.authorization_endpoint).not.toBe('this will not be used');
		} finally {
			// ApplicationConfig is process-wide, so restore or the extensions leak into
			// every later suite in the same run.
			ApplicationConfig.discovery = original;
		}
	});

	describe('with unexpected exceptions', () => {
		afterEach(() => mock.restore());

		it('handles exceptions with json 500 and emits server_error', async () => {
			const spy = mock();
			eventBus.once('server_error', spy);

			// Force the discovery handler to throw while it applies discovery overrides.
			// bun's spyOn can't stub an accessor, so override the getter directly and
			// restore the original descriptor afterwards.
			const config = ApplicationConfig;
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
