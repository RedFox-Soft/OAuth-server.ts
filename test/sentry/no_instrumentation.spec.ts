import { describe, it, expect, beforeAll } from 'bun:test';
import { readFileSync } from 'node:fs';

import bootstrap, { agent } from '../test_helper.js';

/*
 * The integration is not on the request path, asserted two ways: over the responses the server
 * actually sends, and over the source of the module itself.
 *
 * Both are needed because they fail differently. The response sweep catches the symptom — a header
 * that appeared on every reply — while the source assertions catch the cause before it ships,
 * including the case where a hook is registered but happens to add nothing observable yet.
 *
 * The specific thing being prevented: the official Elysia SDK plugin wraps the whole HTTP layer. It
 * writes `sentry-trace` and `baggage` onto every response and opens a span on each of the nine
 * lifecycle phases. Responses must be byte-identical with or without reporting armed, so the plugin
 * cannot be used and this file is what says so.
 */
const SENTRY_SOURCES = [
	'lib/sentry/client.ts',
	'lib/sentry/dispatch.ts',
	'lib/sentry/event.ts',
	'lib/sentry/startup.ts',
	'lib/sentry/transport.ts',
	'lib/sentry/types.ts'
];

function sentrySource(): string {
	return SENTRY_SOURCES.map((f) => readFileSync(f, 'utf8')).join('\n');
}

describe('sentry adds no request-path instrumentation', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	/* The symptom, over a spread of surfaces rather than one endpoint. */
	it('adds no trace headers to any response', async () => {
		const responses = [
			(
				await agent.userinfo.post(
					{},
					{
						headers: { authorization: 'Bearer not-a-token' }
					}
				)
			).response,
			(await agent['.well-known']['openid-configuration'].get()).response,
			(await agent.jwks.get()).response,
			/* A refused grant: the failure path answers through a different branch than a success. */
			(
				await agent.token.post({
					grant_type: 'authorization_code',
					code: 'no-such-code'
				})
			).response
		];

		for (const response of responses) {
			expect(response.headers.get('sentry-trace')).toBeNull();
			expect(response.headers.get('baggage')).toBeNull();
		}
	});

	it('adds no sentry header to an unauthenticated response either', async () => {
		const { response } = await agent.userinfo.post(
			{},
			{
				headers: { authorization: 'Bearer not-a-token' }
			}
		);
		expect(response.headers.get('sentry-trace')).toBeNull();
		expect(response.headers.get('baggage')).toBeNull();
	});

	/* The cause. */
	it('registers no Elysia lifecycle hook', () => {
		const source = sentrySource();
		for (const hook of [
			'onRequest',
			'onError',
			'onAfterHandle',
			'onBeforeHandle',
			'onParse',
			'onTransform',
			'onMapResponse',
			'onAfterResponse',
			'.trace(',
			'.wrap('
		]) {
			expect(source).not.toContain(hook);
		}
	});

	it('never reaches for the Elysia plugin', () => {
		const source = sentrySource();
		expect(source).not.toContain('withElysia');
		expect(source).not.toContain('@sentry/elysia');
	});

	it('does not import Elysia at all', () => {
		expect(sentrySource()).not.toContain("from 'elysia'");
	});

	/*
	 * And the plugin is not installable by accident: it is absent from the dependency list, so
	 * reaching for it is a deliberate act with a lockfile change attached.
	 */
	it('does not depend on the Elysia SDK package', () => {
		const manifest = readFileSync('package.json', 'utf8');
		expect(manifest).not.toContain('@sentry/elysia');
	});
});
