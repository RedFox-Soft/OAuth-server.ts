import { expect } from 'chai';

import provider from '../../lib/index.ts';

describe('default findAccount behavior', () => {
	it('returns a promise', () => {
		const provider = new provider('http://localhost');

		expect(i(provider).configuration.findAccount({}, 'id') instanceof Promise)
			.to.be.true;
	});

	it('resolves to an object with property and accountId property and claims function', () => {
		const provider = new provider('http://localhost');

		return i(provider)
			.configuration.findAccount({}, 'id')
			.then(async (account) => {
				expect(account.accountId).to.equal('id');
				expect(await account.claims()).to.eql({ sub: 'id' });
			});
	});
});
