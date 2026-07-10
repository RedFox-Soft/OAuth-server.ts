import { describe, it, expect } from 'bun:test';
import provider from '../../lib/index.ts';

// Captures the error thrown by `fn` (or throws if it does not throw) so we can
// make assertions about the thrown error's properties — bun's `.toThrow()` only
// matches the message, not arbitrary properties like `error_description`.
function catchError(fn: () => unknown): unknown {
	try {
		fn();
	} catch (err) {
		return err;
	}
	throw new Error('expected function to throw, but it did not');
}

describe('Provider configuration', () => {
	describe('clients', () => {
		it('may contain static clients when these have at least the client_id', () => {
			for (const clients of [[null], [{}]]) {
				const err = catchError(() => {
					provider.init({ clients });
				});
				expect(err).toBeInstanceOf(Error);
				expect(err).toHaveProperty(
					'error_description',
					'client_id is mandatory property for statically configured clients'
				);
			}
		});
		it('client_id must be unique amongst the static clients', () => {
			const err = catchError(() => {
				provider.init({
					clients: [{ clientId: 'foo' }, { clientId: 'foo' }]
				});
			});
			expect(err).toBeInstanceOf(Error);
			expect(err).toHaveProperty(
				'error_description',
				'client_id must be unique amongst statically configured clients'
			);
		});
	});

	describe('acrValues', () => {
		it('only accepts arrays and sets', () => {
			provider.init({
				acrValues: ['bronze', 'silver']
			});
			provider.init({
				acrValues: new Set(['bronze', 'silver'])
			});
			expect(() => {
				provider.init({ acrValues: { bronze: true } });
			}).toThrow('acrValues must be an Array or Set');
		});
	});

	describe('scopes', () => {
		it('only accepts arrays and sets', () => {
			provider.init({ scopes: ['foo', 'bar'] });
			provider.init({
				scopes: new Set(['foo', 'bar'])
			});
			expect(() => {
				provider.init({ scopes: { foo: true } });
			}).toThrow('scopes must be an Array or Set');
		});
	});

	it('validates configuration clientAuthMethods members', () => {
		expect(() => {
			provider.init({ clientAuthMethods: ['foo'] });
		}).toThrow(
			"only supported clientAuthMethods are 'none', 'client_secret_basic', 'client_secret_jwt', 'client_secret_post', and 'private_key_jwt'"
		);
	});
});
