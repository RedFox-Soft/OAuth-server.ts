import { describe, it, expect } from 'bun:test';
import { assertStoredSettingTypes } from 'lib/configs/application.ts';

/*
 * Tested against the function rather than a boot: the stored settings are read once, at import, from a
 * store a child process would have to share with the spec, and the memory store does not. What is pinned
 * is the rule the boot applies to that document.
 */

/**
 * @proves A stored setting whose type is not its setting's is refused at startup, so a value that
 * reached the store around the settings API cannot switch a flag on by being a truthy string.
 */
describe('stored setting types', () => {
	it('refuses a trust flag stored as the string "false", naming it', () => {
		expect(() =>
			assertStoredSettingTypes({ 'mTLS.trustProxyCertificateHeader': 'false' })
		).toThrow(
			'stored setting mTLS.trustProxyCertificateHeader must be a boolean, found string'
		);
	});

	it('refuses a number stored as a string', () => {
		expect(() =>
			assertStoredSettingTypes({ 'rateLimit.strict.max': '10' })
		).toThrow('must be a number');
	});

	it('accepts overrides of the declared types, and leaves a retired key alone', () => {
		expect(() =>
			assertStoredSettingTypes({
				'mTLS.trustProxyCertificateHeader': true,
				'rateLimit.strict.max': 10,
				'deviceFlow.charset': 'digits',
				'a.retired.setting': 'whatever'
			})
		).not.toThrow();
	});
});
