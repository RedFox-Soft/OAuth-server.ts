import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { Elysia } from 'elysia';

import { ApplicationConfig } from 'lib/configs/application.ts';
import { errorStore } from 'lib/adapters/index.ts';
import { errorHandler } from 'lib/shared/authorization_error_handler.ts';
import { flushForTest, resetQueue } from 'lib/error_store/queue.ts';

/*
 * That no credential value can reach the store (FR-004, SC-003).
 *
 * The assertion is deliberately crude and total: serialise everything the store holds for the route
 * under test and assert the secret string does not occur anywhere in it. A field-by-field check would
 * pass while a secret arrived through a field nobody thought to check, which is exactly how this class
 * of leak happens — and the record is built from a whitelist precisely so that this test can be blunt.
 *
 * Every value below is a distinctive sentinel, so a match cannot be a coincidence and a failure names
 * which carrier leaked.
 */
const SECRETS = {
	basicSecret: 'SENTINEL-client-secret-9f1',
	bearer: 'SENTINEL-access-token-a72',
	dpop: 'SENTINEL-dpop-proof-c03',
	cookie: 'SENTINEL-session-cookie-e55',
	password: 'SENTINEL-password-b41',
	clientSecretField: 'SENTINEL-secret-field-d18',
	refreshToken: 'SENTINEL-refresh-token-f60',
	codeVerifier: 'SENTINEL-code-verifier-a09',
	assertion: 'SENTINEL-assertion-jwt-b22'
};

const enabled = ApplicationConfig['errorStore.enabled'];

function faultingApp(route: string) {
	return new Elysia()
		.onError(errorHandler)
		.get(route, () => {
			throw new Error('fault while carrying credentials');
		})
		.post(route, () => {
			throw new Error('fault while carrying credentials');
		});
}

async function storedFor(route: string): Promise<string> {
	await flushForTest();
	const page = await errorStore.list({ route });
	expect(page.total).toBeGreaterThan(0);
	return JSON.stringify(page.groups);
}

function expectNoSecretsIn(serialised: string) {
	for (const [carrier, value] of Object.entries(SECRETS)) {
		expect(serialised, `${carrier} leaked into the store`).not.toContain(value);
	}
}

describe('error store redaction', () => {
	beforeEach(() => {
		ApplicationConfig['errorStore.enabled'] = true;
		resetQueue();
	});

	afterEach(() => {
		ApplicationConfig['errorStore.enabled'] = enabled;
	});

	it('keeps every credential-bearing header out of the record', async () => {
		const route = '/redact-headers';
		const app = faultingApp(route);

		await app.handle(
			new Request(`http://e.ly${route}`, {
				headers: {
					authorization: `Basic ${Buffer.from(`app:${SECRETS.basicSecret}`).toString('base64')}`,
					dpop: SECRETS.dpop,
					cookie: `session=${SECRETS.cookie}`,
					'user-agent': 'sweeper/1.0'
				}
			})
		);

		const stored = await storedFor(route);
		expectNoSecretsIn(stored);
		// The user agent IS kept — it carries no credential and it identifies a misbehaving client.
		expect(stored).toContain('sweeper/1.0');
	});

	it('keeps a bearer token out of the record', async () => {
		const route = '/redact-bearer';
		const app = faultingApp(route);

		await app.handle(
			new Request(`http://e.ly${route}`, {
				headers: { authorization: `Bearer ${SECRETS.bearer}` }
			})
		);

		expectNoSecretsIn(await storedFor(route));
	});

	/*
	 * Query parameters are the one place field *names* are kept, so this is the case where the
	 * names-not-values rule earns its keep: the record must say `client_secret` was submitted without
	 * saying what it was.
	 */
	it('records the names of credential-bearing query fields, never their values', async () => {
		const route = '/redact-query';
		const app = faultingApp(route);

		await app.handle(
			new Request(
				`http://e.ly${route}?client_id=app&client_secret=${SECRETS.clientSecretField}&code_verifier=${SECRETS.codeVerifier}`
			)
		);

		const stored = await storedFor(route);
		expectNoSecretsIn(stored);
		expect(stored).toContain('client_secret');
		expect(stored).toContain('code_verifier');
		expect(stored).toContain('client_id');
	});

	it('keeps a posted credential body out of the record entirely', async () => {
		const route = '/redact-body';
		const app = faultingApp(route);

		await app.handle(
			new Request(`http://e.ly${route}`, {
				method: 'POST',
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({
					grant_type: 'password',
					username: 'someone@example.com',
					password: SECRETS.password,
					refresh_token: SECRETS.refreshToken,
					client_assertion: SECRETS.assertion
				}).toString()
			})
		);

		expectNoSecretsIn(await storedFor(route));
	});

	/*
	 * The likeliest accidental route for a secret into a diagnostic record: an error whose message
	 * interpolates a request value. The message is stored, so this is where the store is most exposed —
	 * and the honest answer is that a message the server itself builds from a secret WILL be stored, so
	 * what is pinned here is that nothing the *request* carried arrives via the message on its own.
	 */
	it('stores the fault message without the request that caused it', async () => {
		const route = '/redact-message';
		const app = new Elysia().onError(errorHandler).get(route, () => {
			throw new Error('upstream refused the request');
		});

		await app.handle(
			new Request(
				`http://e.ly${route}?client_secret=${SECRETS.clientSecretField}`,
				{ headers: { authorization: `Bearer ${SECRETS.bearer}` } }
			)
		);

		const stored = await storedFor(route);
		expectNoSecretsIn(stored);
		expect(stored).toContain('upstream refused the request');
	});

	it('stores no raw stack, on any route', async () => {
		const route = '/redact-stack';
		const app = faultingApp(route);

		await app.handle(new Request(`http://e.ly${route}`));

		const stored = await storedFor(route);
		// A parsed location is kept; the multi-frame stack text is not.
		expect(stored).toContain('redaction.spec');
		expect(stored).not.toContain('\n    at ');
	});
});
