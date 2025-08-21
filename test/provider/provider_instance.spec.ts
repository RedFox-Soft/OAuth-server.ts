import { strict as assert } from 'node:assert';
import { expect } from 'chai';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';

describe('provider instance', () => {
	describe('provider.Client#find', () => {
		it('ignores non-string inputs', async () => {
			const provider = new provider('http://localhost');
			expect(await provider.Client.find([])).to.be.undefined;
			expect(await provider.Client.find(Buffer)).to.be.undefined;
			expect(await provider.Client.find({})).to.be.undefined;
			expect(await provider.Client.find(true)).to.be.undefined;
			expect(await provider.Client.find(undefined)).to.be.undefined;
			expect(await provider.Client.find(64)).to.be.undefined;
		});
	});

	describe('#urlFor', () => {
		it('returns the route for unprefixed issuers', () => {
			const provider = new provider('http://localhost');
			expect(provider.urlFor('authorization')).to.equal(
				'http://localhost/auth'
			);
		});

		it('returns the route for prefixed issuers (1/2)', () => {
			const provider = new provider('http://localhost/op/2.0');
			expect(provider.urlFor('authorization')).to.equal(
				'http://localhost/op/2.0/auth'
			);
		});

		it('returns the route for prefixed issuers (2/2)', () => {
			const provider = new provider('http://localhost/op/2.0/');
			expect(provider.urlFor('authorization')).to.equal(
				'http://localhost/op/2.0/auth'
			);
		});

		it('passes the options', () => {
			const provider = new provider('http://localhost');
			expect(provider.urlFor('resume', { uid: 'foo' })).to.equal(
				'http://localhost/auth/foo'
			);
		});
	});

	describe('adapters', () => {
		const error = new Error('used this adapter');

		it('can be a class', async () => {
			const provider = new provider('https://op.example.com', {
				adapter: class {
					// eslint-disable-next-line
					async find() {
						throw error;
					}
				}
			});
			await assert.rejects(AccessToken.find('tokenValue'), {
				message: 'used this adapter'
			});
			await assert.rejects(Client.find('clientId'), {
				message: 'used this adapter'
			});
		});

		it('can be a class static function', async () => {
			const provider = new provider('https://op.example.com', {
				adapter: class {
					// eslint-disable-next-line
					static factory() {
						// eslint-disable-next-line
						return {
							async find() {
								throw error;
							}
						};
					}
				}.factory
			});
			await assert.rejects(AccessToken.find('tokenValue'), {
				message: 'used this adapter'
			});
			await assert.rejects(Client.find('clientId'), {
				message: 'used this adapter'
			});
		});

		it('can be an arrow function', async () => {
			const provider = new provider('https://op.example.com', {
				adapter: () => ({
					async find() {
						throw error;
					}
				})
			});
			await assert.rejects(AccessToken.find('tokenValue'), {
				message: 'used this adapter'
			});
			await assert.rejects(Client.find('clientId'), {
				message: 'used this adapter'
			});
		});
	});
});
