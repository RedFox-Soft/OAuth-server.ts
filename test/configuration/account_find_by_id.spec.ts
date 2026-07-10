import i from 'lib/helpers/weak_cache.js';
import { describe, it, expect } from 'bun:test';
import provider from '../../lib/index.ts';

describe('default findAccount behavior', () => {
	it('returns a promise', () => {
		provider.init();

		expect(
			i(provider).configuration.findAccount({}, 'id') instanceof Promise
		).toBe(true);
	});

	it('resolves to an object with property and accountId property and claims function', () => {
		provider.init();

		return i(provider)
			.configuration.findAccount({}, 'id')
			.then(async (account) => {
				expect(account.accountId).toBe('id');
				expect(await account.claims()).toEqual({ sub: 'id' });
			});
	});
});
