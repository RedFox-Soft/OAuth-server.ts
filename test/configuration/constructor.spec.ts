import { describe, it, expect, afterEach } from 'bun:test';
import '../../lib/index.ts';
import {
	ApplicationConfig,
	configuration,
	reloadConfiguration
} from 'lib/configs/application.js';

// The collection options are read from ApplicationConfig; there is no provider init step.
// reloadConfiguration re-runs the same validation the server runs at startup, so it still rejects
// a non-Array/Set and an unsupported client auth method — read from the server settings.
/**
 * @proves Collection settings accept only real collections, so a scalar cannot be iterated
 * character by character into scopes; and an operator cannot name an authentication context the
 * server would not report, leave one unnamed, or give one value to two authentications.
 */
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
		const named = {
			password: 'bronze',
			multi_factor: 'silver',
			federated: 'gold'
		};

		it('accepts a value for every authentication it can distinguish', () => {
			ApplicationConfig.acrValues = { ...named };
			reloadConfiguration();
			expect([...configuration.acrValues]).toEqual([
				'bronze',
				'silver',
				'gold'
			]);
		});

		it('refuses a list, which cannot say which authentication a value describes', () => {
			// @ts-expect-error a list, which the validation must refuse
			ApplicationConfig.acrValues = ['bronze', 'silver'];
			expect(() => reloadConfiguration()).toThrow('acrValues must be a map');
		});

		it('refuses an authentication the server cannot distinguish', () => {
			// @ts-expect-error an authentication the server cannot distinguish
			ApplicationConfig.acrValues = { ...named, retina_scan: 'platinum' };
			expect(() => reloadConfiguration()).toThrow(
				"acrValues names 'retina_scan'"
			);
		});

		it('refuses a missing authentication, which would have no context to report', () => {
			const { federated: _dropped, ...missing } = named;
			// @ts-expect-error a map missing an authentication
			ApplicationConfig.acrValues = missing;
			expect(() => reloadConfiguration()).toThrow(
				'acrValues.federated must be a non-empty string'
			);
		});

		it('refuses an empty value', () => {
			ApplicationConfig.acrValues = { ...named, password: '' };
			expect(() => reloadConfiguration()).toThrow(
				'acrValues.password must be a non-empty string'
			);
		});

		it('refuses one value shared by two authentications', () => {
			ApplicationConfig.acrValues = { ...named, multi_factor: 'bronze' };
			expect(() => reloadConfiguration()).toThrow(
				'acrValues.multi_factor repeats the value given to password'
			);
		});

		it('refuses the value reserved for an authentication carrying no confidence', () => {
			ApplicationConfig.acrValues = { ...named, password: '0' };
			expect(() => reloadConfiguration()).toThrow("may not be '0'");
		});
	});

	describe('scopes', () => {
		it('only accepts arrays and sets', () => {
			ApplicationConfig.scopes = ['foo', 'bar'];
			reloadConfiguration();
			// @ts-expect-error a Set is outside the setting's type; validation still accepts one
			ApplicationConfig.scopes = new Set(['foo', 'bar']);
			reloadConfiguration();
			// @ts-expect-error neither a list nor a Set, which the validation must refuse
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
