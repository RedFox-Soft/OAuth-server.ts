import { describe, it, expect, beforeEach, afterEach } from 'bun:test';

import { ApplicationConfig } from 'lib/configs/application.ts';
import {
	initSentry,
	initOptionsForTest,
	isArmed,
	resetForTest
} from 'lib/sentry/client.ts';
import { resetLabelsForTest } from 'lib/sentry/labels.ts';
import { recordingTransport } from 'lib/sentry/transport.ts';

/*
 * The options the client is armed with, guarded as data.
 *
 * This spec exists because of what the official Elysia SDK plugin does by default, which this
 * integration deliberately does not use: it captures failures before the server has decided a
 * response status, attaches the full request URL and headers with no option to stop it, and writes
 * trace headers onto every response. Its own `init` wrapper opts a caller into the Bun defaults
 * minus one integration — that is, into nearly all of them.
 *
 * So "every automatic behaviour is off" is not a preference here, it is the requirement, and it is
 * one line away from being silently reversed by an upgrade or a well-meant edit. These assertions
 * read the options actually handed to init rather than rebuilding what they expect, so a drift in
 * the real call cannot pass.
 */
const previous = {
	enabled: ApplicationConfig['sentry.enabled'],
	dsn: ApplicationConfig['sentry.dsn']
};

describe('sentry client options', () => {
	beforeEach(() => {
		resetForTest();
		ApplicationConfig['sentry.enabled'] = true;
		ApplicationConfig['sentry.dsn'] = 'https://publickey@o0.ingest.invalid/1';
		resetLabelsForTest();
	});

	afterEach(() => {
		resetForTest();
		ApplicationConfig['sentry.enabled'] = previous.enabled;
		ApplicationConfig['sentry.dsn'] = previous.dsn;
		resetLabelsForTest();
	});

	it('arms only when the capability is on', () => {
		ApplicationConfig['sentry.enabled'] = false;
		initSentry();
		expect(isArmed()).toBe(false);
		expect(initOptionsForTest()).toBeUndefined();
	});

	it('arms when the capability is on and a credential is present', () => {
		initSentry();
		expect(isArmed()).toBe(true);
	});

	it('does not arm without a credential', () => {
		ApplicationConfig['sentry.dsn'] = '';
		initSentry();
		expect(isArmed()).toBe(false);
	});

	/* The load-bearing assertion of this file. */
	it('disables every integration the SDK would add on its own', () => {
		initSentry();
		const options = initOptionsForTest();
		expect(options?.defaultIntegrations).toBe(false);
		expect(options?.integrations).toEqual([]);
	});

	/*
	 * No outbound delivery in the default test run, whatever a spec has configured. The transport is
	 * chosen inside the client from NODE_ENV rather than injected by each spec, so a spec that arms
	 * the capability without this harness still cannot reach the network.
	 */
	it('installs the recording transport under the test runner', () => {
		initSentry();
		expect(initOptionsForTest()?.transport).toBe(recordingTransport);
	});

	/*
	 * The environment is NODE_ENV, which the runner sets to 'test' — no setting and no variable of this
	 * feature's own. The instance is the issuer rather than a container hostname.
	 */
	it('labels events from the deployment, not from configuration', () => {
		initSentry();
		const options = initOptionsForTest();
		expect(options?.environment).toBe('test');
		expect(options?.serverName).toBe(process.env.ISSUER);
	});

	/*
	 * The release is the package version. An empty one would be worse than absent: to Sentry a release
	 * of "" is not "no release", it is a release named "", which files every unlabelled deployment
	 * under one heading — so the resolver omits the option entirely rather than sending a blank.
	 */
	it('labels the release with the package version', async () => {
		const manifest = (await import('../../package.json', {
			with: { type: 'json' }
		}).catch(() => null)) as { default?: { version?: string } } | null;
		initSentry();
		const release = initOptionsForTest()?.release;
		expect(release).toBeString();
		expect(release).not.toBe('');
		if (manifest?.default?.version) {
			expect(release).toBe(manifest.default.version);
		}
	});

	it('is idempotent', () => {
		initSentry();
		const first = initOptionsForTest();
		initSentry();
		expect(initOptionsForTest()).toBe(first);
	});
});
