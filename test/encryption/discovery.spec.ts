import { describe, it, beforeAll } from 'bun:test';
import { expect } from 'chai';

import bootstrap, { agent } from '../test_helper.js';

describe('configuration features.encryption', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url)();
	});

	it('extends discovery', async () => {
		const { data, status } =
			await agent['.well-known']['openid-configuration'].get();

		expect(status).to.equal(200);
		expect(data).to.contain.keys(
			'id_token_encryption_alg_values_supported',
			'id_token_encryption_enc_values_supported',
			'request_object_encryption_alg_values_supported',
			'request_object_encryption_enc_values_supported',
			'userinfo_encryption_alg_values_supported',
			'userinfo_encryption_enc_values_supported',
			'introspection_encryption_alg_values_supported',
			'introspection_encryption_enc_values_supported'
		);
	});
});
