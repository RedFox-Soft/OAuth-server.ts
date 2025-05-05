import { expect } from 'chai';

import redirectUri from '../../lib/helpers/redirect_uri.ts';

describe('redirectUri helper', () => {
	it('does not modify the redirect_uri when it does not have path', () => {
		const result = redirectUri('http://client.example.com', {
			some: 'payload'
		});

		expect(result).to.equal('http://client.example.com/?some=payload');
	});

	it('extends the query if part of the redirect_uri', () => {
		const result = redirectUri('http://client.example.com/?other=stuff', {
			some: 'payload'
		});

		expect(result).to.equal(
			'http://client.example.com/?other=stuff&some=payload'
		);
	});

	it('payload comes first', () => {
		const result = redirectUri('http://client.example.com/?some=paylod', {
			some: 'other payload'
		});

		expect(result).to.equal('http://client.example.com/?some=other+payload');
	});
});
