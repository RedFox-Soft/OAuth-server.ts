import { describe, it, beforeAll, afterAll, expect } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { provider } from 'lib/provider.js';
import { ApplicationConfig } from 'lib/configs/application.js';

describe('configuration features.deviceFlow', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('extends discovery', async () => {
		const { status, data } =
			await agent['.well-known']['openid-configuration'].get();
		expect(status).toBe(200);
		expect(data).toHaveProperty('device_authorization_endpoint');
	});

	it('can only be configured with digits and base-20 charset', () => {
		const charset = ApplicationConfig['deviceFlow.charset'];
		const mask = ApplicationConfig['deviceFlow.mask'];
		try {
			ApplicationConfig['deviceFlow.enabled'] = true;

			ApplicationConfig['deviceFlow.charset'] = 'digits';
			expect(() => provider.init({})).not.toThrow();

			ApplicationConfig['deviceFlow.charset'] = 'base-20';
			expect(() => provider.init({})).not.toThrow();

			ApplicationConfig['deviceFlow.charset'] = 'foo';
			expect(() => provider.init({})).toThrow(
				'only supported charsets are "base-20" and "digits"'
			);
		} finally {
			ApplicationConfig['deviceFlow.charset'] = charset;
			ApplicationConfig['deviceFlow.mask'] = mask;
		}
	});

	it('can be configured with a mask', () => {
		const charset = ApplicationConfig['deviceFlow.charset'];
		const mask = ApplicationConfig['deviceFlow.mask'];
		try {
			ApplicationConfig['deviceFlow.enabled'] = true;
			ApplicationConfig['deviceFlow.charset'] = 'base-20';

			ApplicationConfig['deviceFlow.mask'] = '*** *** ***';
			expect(() => provider.init({})).not.toThrow();

			ApplicationConfig['deviceFlow.mask'] = '***-***-***';
			expect(() => provider.init({})).not.toThrow();

			ApplicationConfig['deviceFlow.mask'] = '***.***.***';
			expect(() => provider.init({})).toThrow(
				'mask can only contain asterisk("*"), hyphen-minus("-") and space(" ") characters'
			);
		} finally {
			ApplicationConfig['deviceFlow.charset'] = charset;
			ApplicationConfig['deviceFlow.mask'] = mask;
		}
	});
});
