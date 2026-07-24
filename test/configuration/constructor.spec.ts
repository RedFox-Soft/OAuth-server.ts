import { describe, it, expect } from 'bun:test';
import provider from '../../lib/index.ts';

describe('Provider configuration', () => {
	describe('acrValues', () => {
		it('only accepts arrays and sets', () => {
			provider.init({
				acrValues: ['bronze', 'silver']
			});
			provider.init({
				acrValues: new Set(['bronze', 'silver'])
			});
			expect(() => {
				provider.init({ acrValues: { bronze: true } });
			}).toThrow('acrValues must be an Array or Set');
		});
	});

	describe('scopes', () => {
		it('only accepts arrays and sets', () => {
			provider.init({ scopes: ['foo', 'bar'] });
			provider.init({
				scopes: new Set(['foo', 'bar'])
			});
			expect(() => {
				provider.init({ scopes: { foo: true } });
			}).toThrow('scopes must be an Array or Set');
		});
	});

	it('validates configuration clientAuthMethods members', () => {
		expect(() => {
			provider.init({ clientAuthMethods: ['foo'] });
		}).toThrow(
			"only supported clientAuthMethods are 'none', 'client_secret_basic', 'client_secret_jwt', 'client_secret_post', and 'private_key_jwt'"
		);
	});
});
