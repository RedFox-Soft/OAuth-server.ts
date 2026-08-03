import { describe, it, expect } from 'bun:test';
import { validateConfiguration } from 'lib/configs/configuration.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';

/*
 * Descriptor validation, tested against the pure validator. This is the single definition the
 * administrative PUT reaches through validateEffectiveConfig, so what is pinned here is what a
 * super-admin cannot persist — see test/admin/settings.spec.ts for the API side of the same rules.
 */
const withTypes = (types: unknown) => ({
	...ApplicationConfig,
	'richAuthorizationRequests.enabled': true,
	'resourceIndicators.enabled': true,
	'richAuthorizationRequests.types': types
});

describe('features.richAuthorizationRequests.types validation', () => {
	it('accepts a minimal descriptor carrying only a label', () => {
		expect(() =>
			validateConfiguration(withTypes({ 'urn:t': { label: 'T' } }))
		).not.toThrow();
	});

	it('accepts constraints over the common fields', () => {
		expect(() =>
			validateConfiguration(
				withTypes({
					'urn:t': {
						label: 'T',
						fields: {
							actions: { required: true, allowed: ['a'] },
							locations: {},
							datatypes: { allowed: ['d'] },
							privileges: { required: false },
							identifier: { required: true }
						},
						allowUnknownFields: true
					}
				})
			)
		).not.toThrow();
	});

	/*
	 * D4. With no types every authorization_details value is refused before any hook runs, so a switch
	 * that is on and an empty map is never what an operator meant — and it was the default, which is
	 * why the feature could not work out of the box.
	 */
	it('rejects the feature enabled with no types at all', () => {
		expect(() => validateConfiguration(withTypes({}))).toThrow(
			/must declare at least one type/
		);
	});

	it('rejects a non-object map', () => {
		expect(() => validateConfiguration(withTypes([]))).toThrow(
			/must be an object/
		);
	});

	it('rejects a descriptor with no label', () => {
		expect(() => validateConfiguration(withTypes({ 'urn:t': {} }))).toThrow(
			/label must be a non-empty string/
		);
	});

	it('rejects a descriptor whose label is empty or not a string', () => {
		expect(() =>
			validateConfiguration(withTypes({ 'urn:t': { label: '' } }))
		).toThrow(/label must be a non-empty string/);
		expect(() =>
			validateConfiguration(withTypes({ 'urn:t': { label: 7 } }))
		).toThrow(/label must be a non-empty string/);
	});

	it('rejects a constraint on a field that is not one of the five common fields', () => {
		expect(() =>
			validateConfiguration(
				withTypes({ 'urn:t': { label: 'T', fields: { nope: {} } } })
			)
		).toThrow(/must only constrain/);
	});

	// `identifier` is single-valued, so a permitted-value set restricts nothing meaningful.
	it('rejects allowed values on the identifier field', () => {
		expect(() =>
			validateConfiguration(
				withTypes({
					'urn:t': { label: 'T', fields: { identifier: { allowed: ['x'] } } }
				})
			)
		).toThrow(/must not declare allowed values/);
	});

	it('rejects a malformed allowed list', () => {
		for (const allowed of [[], ['', 'a'], 'a', [1]]) {
			expect(() =>
				validateConfiguration(
					withTypes({
						'urn:t': { label: 'T', fields: { actions: { allowed } } }
					})
				)
			).toThrow(/allowed must be a non-empty array of non-empty strings/);
		}
	});

	it('rejects non-boolean required and allowUnknownFields', () => {
		expect(() =>
			validateConfiguration(
				withTypes({
					'urn:t': { label: 'T', fields: { actions: { required: 'yes' } } }
				})
			)
		).toThrow(/required must be a boolean/);
		expect(() =>
			validateConfiguration(
				withTypes({ 'urn:t': { label: 'T', allowUnknownFields: 'yes' } })
			)
		).toThrow(/allowUnknownFields must be a boolean/);
	});

	/*
	 * The code-registered validator survives as an optional escape hatch. It is no longer required —
	 * that requirement is what made the key function-valued, and therefore unconfigurable by an
	 * operator — but a value supplied in an in-process bootstrap must still be callable.
	 */
	it('accepts an optional validator and rejects a non-function one', () => {
		expect(() =>
			validateConfiguration(
				withTypes({ 'urn:t': { label: 'T', validate() {} } })
			)
		).not.toThrow();
		expect(() =>
			validateConfiguration(
				withTypes({ 'urn:t': { label: 'T', validate: 'nope' } })
			)
		).toThrow(/validate must be a function/);
	});

	it('ignores the types map entirely when the feature is disabled', () => {
		expect(() =>
			validateConfiguration({
				...ApplicationConfig,
				'richAuthorizationRequests.enabled': false,
				'richAuthorizationRequests.types': { 'urn:t': { nonsense: true } }
			})
		).not.toThrow();
	});
});
