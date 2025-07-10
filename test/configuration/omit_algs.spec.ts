import { describe, it, expect } from 'bun:test';
import provider from '../../lib/index.ts';
import { idTokenSigningAlgValues } from 'lib/configs/jwaAlgorithms.js';
import { getAlgorithm } from 'lib/helpers/initialize_keystore.js';
import { JWKS_KEYS } from 'lib/configs/env.js';

describe('Provider declaring supported algorithms', () => {
	it('validates the configuration properties', () => {
		expect(() => {
			provider.init('https://op.example.com', {
				// eslint-disable-line no-new
				enabledJWA: {
					invalidProperty: ['HS256', 'RS256']
				}
			});
		}).toThrow('invalid property enabledJWA.invalidProperty provided');
	});

	it('validates only implemented algs are provided', () => {
		expect(() => {
			provider.init('https://op.example.com', {
				// eslint-disable-line no-new
				enabledJWA: {
					clientAuthSigningAlgValues: ['none']
				}
			});
		}).toThrow(
			'unsupported enabledJWA.clientAuthSigningAlgValues algorithm provided'
		);
	});

	it('Validate idTokenSigningAlgValues which depend of ENV JWKS', async () => {
		const alg = getAlgorithm(JWKS_KEYS);
		expect(idTokenSigningAlgValues).toEqual(['HS256', ...alg.sign]);
	});
});
