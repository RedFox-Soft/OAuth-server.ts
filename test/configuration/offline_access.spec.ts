import { expect } from 'chai';
import { describe, it } from 'bun:test';
import provider from '../../lib/index.ts';

describe('Provider declaring support for refresh_token grant type', () => {
	it('is enabled by default', () => {
		provider.init();
		expect(i(provider).configuration.grantTypes).to.contain('refresh_token');
	});

	it('isnt enabled when offline_access isnt amongst the scopes', () => {
		provider.init({
			scopes: ['openid']
		});
		expect(i(provider).configuration.grantTypes).not.to.contain(
			'refresh_token'
		);
	});

	it('is enabled when offline_access isnt amongst the scopes', () => {
		provider.init({
			scopes: ['openid', 'offline_access']
		});
		expect(i(provider).configuration.grantTypes).to.contain('refresh_token');
	});

	it('is enabled when issueRefreshToken configuration function is configured', () => {
		provider.init({
			scopes: ['openid'],
			issueRefreshToken() {
				return true;
			}
		});
		expect(i(provider).configuration.grantTypes).to.contain('refresh_token');
	});
});
