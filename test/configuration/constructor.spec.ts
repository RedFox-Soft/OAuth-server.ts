/* eslint-disable no-new */

import { expect } from 'chai';
import { describe, it } from 'bun:test';
import provider from '../../lib/index.ts';

describe('Provider configuration', () => {
	describe('clients', () => {
		it('may contain static clients when these have at least the client_id', () => {
			expect(() => {
				provider.init('http://localhost:3000', {
					clients: [null]
				});
			})
				.to.throw(Error)
				.with.property(
					'error_description',
					'client_id is mandatory property for statically configured clients'
				);
			expect(() => {
				provider.init('http://localhost:3000', {
					clients: [{}]
				});
			})
				.to.throw(Error)
				.with.property(
					'error_description',
					'client_id is mandatory property for statically configured clients'
				);
		});
		it('client_id must be unique amongst the static clients', () => {
			expect(() => {
				provider.init('http://localhost:3000', {
					clients: [{ client_id: 'foo' }, { client_id: 'foo' }]
				});
			})
				.to.throw(Error)
				.with.property(
					'error_description',
					'client_id must be unique amongst statically configured clients'
				);
		});
	});

	describe('acrValues', () => {
		it('only accepts arrays and sets', () => {
			provider.init('http://localhost:3000', {
				acrValues: ['bronze', 'silver']
			});
			provider.init('http://localhost:3000', {
				acrValues: new Set(['bronze', 'silver'])
			});
			expect(() => {
				provider.init('http://localhost:3000', { acrValues: { bronze: true } });
			}).to.throw('acrValues must be an Array or Set');
		});
	});

	describe('subjectTypes', () => {
		it('only accepts arrays and sets', () => {
			provider.init('http://localhost:3000', { subjectTypes: ['public'] });
			provider.init('http://localhost:3000', {
				subjectTypes: new Set(['public'])
			});
			expect(() => {
				provider.init('http://localhost:3000', {
					subjectTypes: { bronze: true }
				});
			}).to.throw('subjectTypes must be an Array or Set');
		});
	});

	describe('scopes', () => {
		it('only accepts arrays and sets', () => {
			provider.init('http://localhost:3000', { scopes: ['foo', 'bar'] });
			provider.init('http://localhost:3000', {
				scopes: new Set(['foo', 'bar'])
			});
			expect(() => {
				provider.init('http://localhost:3000', { scopes: { foo: true } });
			}).to.throw('scopes must be an Array or Set');
		});
	});

	it('validates configuration clientAuthMethods members', () => {
		expect(() => {
			provider.init('http://localhost:3000', { clientAuthMethods: ['foo'] });
		}).to.throw(
			"only supported clientAuthMethods are 'none', 'client_secret_basic', 'client_secret_jwt', 'client_secret_post', and 'private_key_jwt'"
		);
	});
});
