import { describe, it, expect, afterEach } from 'bun:test';
import provider from '../../lib/index.ts';
import {
	ApplicationConfig,
	reloadConfiguration
} from 'lib/configs/application.js';

// The collection options are read from ApplicationConfig; there is no provider init step.
// reloadConfiguration re-runs the same validation the server runs at startup, so it still rejects
// a non-Array/Set and an unsupported client auth method — read from the server settings.
describe('Provider configuration', () => {
	const original = {
		acrValues: ApplicationConfig.acrValues,
		scopes: ApplicationConfig.scopes,
		clientAuthMethods: ApplicationConfig.clientAuthMethods
	};

	afterEach(() => {
		Object.assign(ApplicationConfig, original);
		reloadConfiguration();
	});

	describe('acrValues', () => {
		it('only accepts arrays and sets', () => {
			ApplicationConfig.acrValues = ['bronze', 'silver'];
			reloadConfiguration();
			ApplicationConfig.acrValues = new Set(['bronze', 'silver']);
			reloadConfiguration();
			ApplicationConfig.acrValues = { bronze: true };
			expect(() => {
				reloadConfiguration();
			}).toThrow('acrValues must be an Array or Set');
		});
	});

	describe('scopes', () => {
		it('only accepts arrays and sets', () => {
			ApplicationConfig.scopes = ['foo', 'bar'];
			reloadConfiguration();
			ApplicationConfig.scopes = new Set(['foo', 'bar']);
			reloadConfiguration();
			ApplicationConfig.scopes = { foo: true };
			expect(() => {
				reloadConfiguration();
			}).toThrow('scopes must be an Array or Set');
		});
	});

	it('validates configuration clientAuthMethods members', () => {
		ApplicationConfig.clientAuthMethods = ['foo'];
		expect(() => {
			reloadConfiguration();
		}).toThrow(
			"only supported clientAuthMethods are 'none', 'client_secret_basic', 'client_secret_jwt', 'client_secret_post', and 'private_key_jwt'"
		);
	});
});
