import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';

describe('configuration features.encryption', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url)();
	});

	it('extends discovery', async () => {
		const { data, status } =
			await agent['.well-known']['openid-configuration'].get();

		expect(status).toBe(200);
		expect(data).toContainKeys([
			'id_token_encryption_alg_values_supported',
			'id_token_encryption_enc_values_supported',
			'request_object_encryption_alg_values_supported',
			'request_object_encryption_enc_values_supported',
			'userinfo_encryption_alg_values_supported',
			'userinfo_encryption_enc_values_supported',
			'introspection_encryption_alg_values_supported',
			'introspection_encryption_enc_values_supported'
		]);
	});
});
