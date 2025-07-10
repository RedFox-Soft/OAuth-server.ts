import { expect } from 'chai';
import { generateKeyPair, exportJWK } from 'jose';
import { describe, it } from 'bun:test';
import provider from '../../lib/index.ts';
import '../test_helper.js';

describe('Provider declaring supported algorithms', () => {
	it('validates the configuration properties', () => {
		expect(() => {
			provider.init('https://op.example.com', {
				// eslint-disable-line no-new
				enabledJWA: {
					invalidProperty: ['HS256', 'RS256']
				}
			});
		}).to.throw('invalid property enabledJWA.invalidProperty provided');
	});

	it('validates an array is provided', () => {
		expect(() => {
			provider.init('https://op.example.com', {
				// eslint-disable-line no-new
				enabledJWA: {
					idTokenSigningAlgValues: new Set(['HS256', 'RS256'])
				}
			});
		}).to.throw(
			'invalid type for enabledJWA.idTokenSigningAlgValues provided, expected Array'
		);
	});

	it('validates only implemented algs are provided', () => {
		expect(() => {
			provider.init('https://op.example.com', {
				// eslint-disable-line no-new
				enabledJWA: {
					clientAuthSigningAlgValues: ['none']
				}
			});
		}).to.throw(
			'unsupported enabledJWA.clientAuthSigningAlgValues algorithm provided'
		);
	});

	it('idTokenSigningAlgValues', async () => {
		const { privateKey } = await generateKeyPair('RS256', {
			extractable: true
		});
		const jwk = await exportJWK(privateKey);
		jwk.alg = 'RS256';
		provider.init('https://op.example.com', {
			enabledJWA: {
				idTokenSigningAlgValues: ['HS256', 'RS256']
			},
			jwks: { keys: [jwk] }
		});

		expect(i(provider).configuration.idTokenSigningAlgValues).to.eql([
			'HS256',
			'RS256'
		]);
	});
});
