import { describe, it, expect } from 'bun:test';
import { idTokenSigningAlgValues } from 'lib/configs/jwaAlgorithms.js';
import { getAlgorithm } from 'lib/configs/verifyJWKs.js';
import { JWKS_KEYS } from 'lib/configs/env.js';

describe('Provider declaring supported algorithms', () => {
	it('Validate idTokenSigningAlgValues which depend of ENV JWKS', async () => {
		const alg = getAlgorithm(JWKS_KEYS);
		expect(idTokenSigningAlgValues).toEqual(['HS256', ...alg.sign]);
	});
});
