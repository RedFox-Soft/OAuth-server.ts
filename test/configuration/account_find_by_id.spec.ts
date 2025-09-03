import { expect } from 'chai';
import { describe, it } from 'bun:test';
import provider from '../../lib/index.ts';

describe('default findAccount behavior', () => {
	it('returns a promise', () => {
		provider.init();

		expect(i(provider).configuration.findAccount({}, 'id') instanceof Promise)
			.to.be.true;
	});

	it('resolves to an object with property and accountId property and claims function', () => {
		provider.init();

		return i(provider)
			.configuration.findAccount({}, 'id')
			.then(async (account) => {
				expect(account.accountId).to.equal('id');
				expect(await account.claims()).to.eql({ sub: 'id' });
			});
	});
});
