import { expect } from 'chai';
import { describe, it } from 'bun:test';
import provider from '../../lib/index.ts';

describe('response_types Provider configuration', () => {
	it('fixes common issues', () => {
		provider.init('https://op.example.com', {
			responseTypes: ['code', 'none']
		});
		expect(i(provider).configuration.responseTypes).to.eql(['code', 'none']);
	});

	it('throws when invalid types are configured', () => {
		expect(() => {
			provider.init('https://op.example.com', {
				responseTypes: ['id_token tokencode']
			});
		}).to.throw('unsupported response type: id_token tokencode');
	});

	it('throws when unsupported types are configured', () => {
		expect(() => {
			provider.init('https://op.example.com', {
				responseTypes: ['token']
			});
		}).to.throw('unsupported response type: token');
	});

	it('validates none is always standalone', () => {
		expect(() => {
			provider.init('https://op.example.com', {
				responseTypes: ['none code']
			});
		}).to.throw('unsupported response type: none code');
	});
});
