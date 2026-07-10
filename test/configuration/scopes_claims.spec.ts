import i from 'lib/helpers/weak_cache.js';
import { describe, it, expect } from 'bun:test';
import provider from '../../lib/index.ts';

describe('custom claims', () => {
	it('allows for claims to be added under openid scope using array syntax', () => {
		provider.init({
			claims: { openid: ['foo'] }
		});

		expect(i(provider).configuration.claims.openid).toEqual({
			sub: null,
			foo: null
		});
	});

	it('allows for claims to be added under openid scope using object syntax', () => {
		provider.init({
			claims: { openid: { foo: null } }
		});

		expect(i(provider).configuration.claims.openid).toEqual({
			sub: null,
			foo: null
		});
	});

	it('detects new scopes from claims definition', () => {
		provider.init({
			claims: {
				insurance: ['company_name', 'coverage'],
				payment: {
					preferred_method: null
				}
			}
		});

		expect(i(provider).configuration.scopes).toContain('insurance', 'payment');
	});

	it('removes the acr claim if no acrs are configured', () => {
		provider.init({ acrValues: [] });

		expect(i(provider).configuration.claimsSupported).not.toContain('acr');
	});
});
