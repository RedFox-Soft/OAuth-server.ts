import { describe, it, expect, afterEach } from 'bun:test';
import provider from '../../lib/index.ts';
import { ApplicationConfig } from 'lib/configs/application.js';

// The collection options are read from ApplicationConfig — provider.init takes no configuration.
// The initialisation-time validation is unchanged: it still rejects a non-Array/Set and an
// unsupported client auth method, it just reads the offending value from the server settings.
describe('Provider configuration', () => {
	const original = {
		acrValues: ApplicationConfig.acrValues,
		scopes: ApplicationConfig.scopes,
		clientAuthMethods: ApplicationConfig.clientAuthMethods
	};

	afterEach(() => {
		Object.assign(ApplicationConfig, original);
		provider.init();
	});

	describe('acrValues', () => {
		it('only accepts arrays and sets', () => {
			ApplicationConfig.acrValues = ['bronze', 'silver'];
			provider.init();
			ApplicationConfig.acrValues = new Set(['bronze', 'silver']);
			provider.init();
			ApplicationConfig.acrValues = { bronze: true };
			expect(() => {
				provider.init();
			}).toThrow('acrValues must be an Array or Set');
		});
	});

	describe('scopes', () => {
		it('only accepts arrays and sets', () => {
			ApplicationConfig.scopes = ['foo', 'bar'];
			provider.init();
			ApplicationConfig.scopes = new Set(['foo', 'bar']);
			provider.init();
			ApplicationConfig.scopes = { foo: true };
			expect(() => {
				provider.init();
			}).toThrow('scopes must be an Array or Set');
		});
	});

	it('validates configuration clientAuthMethods members', () => {
		ApplicationConfig.clientAuthMethods = ['foo'];
		expect(() => {
			provider.init();
		}).toThrow(
			"only supported clientAuthMethods are 'none', 'client_secret_basic', 'client_secret_jwt', 'client_secret_post', and 'private_key_jwt'"
		);
	});
});
