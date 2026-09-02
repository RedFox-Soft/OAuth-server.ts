import { describe, it, expect } from 'bun:test';
import { validateConfiguration } from 'lib/configs/configuration.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';

/*
 * The Sentry integration's configuration invariants, tested against the pure validator — the single
 * definition the administrative PUT reaches through validateEffectiveConfig, so what is pinned here
 * is what a super-admin cannot persist and what a deployment cannot boot with.
 *
 * A usable DSN for the cases that need one to be present. Never sent anywhere: no test in this file
 * arms a client, and the host is deliberately one that does not resolve.
 */
const DSN = 'https://publickey@o0.ingest.invalid/1';

const withSentry = (overrides: Record<string, unknown>) => ({
	...ApplicationConfig,
	...overrides
});

describe('sentry configuration validation', () => {
	it('accepts the shipped defaults', () => {
		expect(() => validateConfiguration({ ...ApplicationConfig })).not.toThrow();
	});

	/*
	 * Enabling with nothing to send to is a configuration error, not a silent no-op. The message has
	 * to name the credential: an operator who has just switched this on and restarted needs to be
	 * told what is missing, not that something is.
	 */
	it('rejects enabling with no credential', () => {
		expect(() =>
			validateConfiguration(
				withSentry({
					'sentry.enabled': true,
					'sentry.dsn': '',
					'errorStore.enabled': true
				})
			)
		).toThrow('sentry.dsn');
	});

	it('rejects enabling with a credential that is only whitespace', () => {
		expect(() =>
			validateConfiguration(
				withSentry({
					'sentry.enabled': true,
					'sentry.dsn': '   ',
					'errorStore.enabled': true
				})
			)
		).toThrow('sentry.dsn');
	});

	it('rejects enabling with an unparseable credential', () => {
		expect(() =>
			validateConfiguration(
				withSentry({
					'sentry.enabled': true,
					'sentry.dsn': 'not-a-dsn',
					'errorStore.enabled': true
				})
			)
		).toThrow('sentry.dsn');
	});

	/*
	 * The invariant that makes "failures never leave without also being recorded" unexpressible
	 * rather than merely forbidden. Outbound reporting is derived from the internal record, so
	 * reporting without recording is not a degraded mode — it is a state with no event source.
	 */
	it('rejects enabling without the error store', () => {
		expect(() =>
			validateConfiguration(
				withSentry({
					'sentry.enabled': true,
					'sentry.dsn': DSN,
					'errorStore.enabled': false
				})
			)
		).toThrow('errorStore.enabled');
	});

	it('accepts enabling with a credential and the error store on', () => {
		expect(() =>
			validateConfiguration(
				withSentry({
					'sentry.enabled': true,
					'sentry.dsn': DSN,
					'errorStore.enabled': true
				})
			)
		).not.toThrow();
	});

	/*
	 * A credential present while reporting is off is not an error and must not activate anything.
	 * An operator preparing the setting before switching it on is a normal sequence.
	 */
	it('accepts a stored credential while reporting is off', () => {
		expect(() =>
			validateConfiguration(
				withSentry({ 'sentry.enabled': false, 'sentry.dsn': DSN })
			)
		).not.toThrow();
	});
});
