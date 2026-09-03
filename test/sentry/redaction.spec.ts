import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { Elysia } from 'elysia';

import { ApplicationConfig } from 'lib/configs/application.ts';
import { errorHandler } from 'lib/shared/authorization_error_handler.ts';
import { flushForTest, resetQueue } from 'lib/error_store/queue.ts';
import { resetOriginSalt } from 'lib/error_store/redact.ts';
import { initSentry, resetForTest as resetClient } from 'lib/sentry/client.ts';
import {
	flushForTest as flushSentry,
	refusedCount,
	resetForTest as resetDispatch
} from 'lib/sentry/dispatch.ts';
import { clearRecorded, recordedEnvelopes } from 'lib/sentry/transport.ts';

/*
 * What does not leave this server, asserted over the envelopes that would have been delivered.
 *
 * This file is the measurable form of "zero events carry anything outside the permitted list". It is
 * the reason the transport is swapped rather than the network merely being unreachable: an assertion
 * needs the bytes, and a test that only proved nothing was *sent* could not prove nothing *would*
 * have been.
 *
 * Every secret below is a distinctive sentinel so a substring search is meaningful — a value like
 * "secret" would match this file's own prose in a serialized event and pass for the wrong reason.
 */
const SENTINELS = {
	clientSecret: 'ZZclientsecretZZ',
	code: 'ZZauthzcodeZZ',
	refresh: 'ZZrefreshtokenZZ',
	access: 'ZZaccesstokenZZ',
	password: 'ZZpasswordZZ',
	state: 'ZZstateZZ',
	challenge: 'ZZcodechallengeZZ',
	loginHint: 'ZZloginhintZZ',
	idTokenHint: 'ZZidtokenhintZZ',
	requestUri: 'ZZrequesturiZZ',
	dpop: 'ZZdpopproofZZ',
	cookie: 'ZZsessioncookieZZ',
	address: '203.0.113.7'
};

const previous = {
	store: ApplicationConfig['errorStore.enabled'],
	level: ApplicationConfig['errorStore.originCaptureLevel'],
	sentry: ApplicationConfig['sentry.enabled'],
	dsn: ApplicationConfig['sentry.dsn']
};

function capturedEvents(): Record<string, unknown>[] {
	const events: Record<string, unknown>[] = [];
	for (const [, items] of recordedEnvelopes()) {
		for (const [header, payload] of items as [{ type?: string }, unknown][]) {
			if (header?.type === 'event') {
				events.push(payload as Record<string, unknown>);
			}
		}
	}
	return events;
}

/* Everything the transport was handed, as one string — the search space for a leak. */
function serialized(): string {
	return JSON.stringify(recordedEnvelopes());
}

async function provoke(route: string, request: Request) {
	const app = new Elysia().onError(errorHandler).all(route, () => {
		throw new Error('deliberate fault');
	});
	const response = await app.handle(request);
	await flushForTest();
	await flushSentry();
	return response;
}

describe('sentry redaction', () => {
	beforeEach(() => {
		resetQueue();
		resetOriginSalt();
		resetDispatch();
		resetClient();
		clearRecorded();
		ApplicationConfig['errorStore.enabled'] = true;
		ApplicationConfig['errorStore.originCaptureLevel'] = 'anonymized';
		ApplicationConfig['sentry.enabled'] = true;
		ApplicationConfig['sentry.dsn'] = 'https://publickey@o0.ingest.invalid/1';
		initSentry();
	});

	afterEach(() => {
		resetDispatch();
		resetClient();
		clearRecorded();
		ApplicationConfig['errorStore.enabled'] = previous.store;
		ApplicationConfig['errorStore.originCaptureLevel'] = previous.level;
		ApplicationConfig['sentry.enabled'] = previous.sentry;
		ApplicationConfig['sentry.dsn'] = previous.dsn;
	});

	it('carries no credential material from a token request', async () => {
		await provoke(
			'/redact-token',
			new Request('http://e.ly/redact-token', {
				method: 'POST',
				headers: {
					authorization: `Basic ${Buffer.from(`app:${SENTINELS.clientSecret}`).toString('base64')}`,
					dpop: SENTINELS.dpop,
					cookie: `session=${SENTINELS.cookie}`,
					'content-type': 'application/x-www-form-urlencoded'
				},
				body: new URLSearchParams({
					grant_type: 'authorization_code',
					code: SENTINELS.code,
					refresh_token: SENTINELS.refresh,
					client_secret: SENTINELS.clientSecret,
					password: SENTINELS.password
				}).toString()
			})
		);

		expect(capturedEvents()).toHaveLength(1);
		const body = serialized();
		for (const value of [
			SENTINELS.clientSecret,
			SENTINELS.code,
			SENTINELS.refresh,
			SENTINELS.password,
			SENTINELS.dpop,
			SENTINELS.cookie
		]) {
			expect(body).not.toContain(value);
		}
	});

	/*
	 * The authorization endpoint is the case that decided the design: its query string carries state,
	 * a code challenge and identity hints, and on an error redirect the code itself. The official
	 * Elysia SDK plugin attaches the full request URL to every event with no option to stop it, which
	 * is why this integration does not use it.
	 */
	it('carries no authorization request parameters', async () => {
		const query = new URLSearchParams({
			client_id: 'app',
			state: SENTINELS.state,
			code_challenge: SENTINELS.challenge,
			login_hint: SENTINELS.loginHint,
			id_token_hint: SENTINELS.idTokenHint,
			request_uri: SENTINELS.requestUri,
			code: SENTINELS.code
		});
		await provoke(
			'/redact-authorize',
			new Request(`http://e.ly/redact-authorize?${query.toString()}`)
		);

		expect(capturedEvents()).toHaveLength(1);
		const body = serialized();
		for (const value of [
			SENTINELS.state,
			SENTINELS.challenge,
			SENTINELS.loginHint,
			SENTINELS.idTokenHint,
			SENTINELS.requestUri,
			SENTINELS.code
		]) {
			expect(body).not.toContain(value);
		}
	});

	it('carries no request url or query string', async () => {
		await provoke(
			'/redact-url',
			new Request(`http://e.ly/redact-url?state=${SENTINELS.state}`)
		);

		const [event] = capturedEvents();
		expect(event).not.toHaveProperty('request');
		expect(serialized()).not.toContain('redact-url?');
		expect(serialized()).not.toContain('http://e.ly/redact-url');
	});

	/*
	 * Field *names* are permitted and values are not, so this asserts both halves at once: the names
	 * arrive (they are the "what did the request carry" answer) while the values do not.
	 */
	it('carries submitted field names without their values', async () => {
		await provoke(
			'/redact-names',
			new Request(
				`http://e.ly/redact-names?state=${SENTINELS.state}&client_id=app`
			)
		);

		const fault = (capturedEvents()[0].contexts as Record<string, unknown>)
			.fault as Record<string, unknown>;
		expect(fault.submittedFields).toContain('state');
		expect(JSON.stringify(fault.submittedFields)).not.toContain(
			SENTINELS.state
		);
	});

	it('carries no end-user identity', async () => {
		await provoke('/redact-user', new Request('http://e.ly/redact-user'));
		const [event] = capturedEvents();
		expect(event).not.toHaveProperty('user');
		expect(serialized()).not.toContain('@example.com');
	});

	it('carries no user agent', async () => {
		await provoke(
			'/redact-ua',
			new Request('http://e.ly/redact-ua', {
				headers: { 'user-agent': 'ZZuseragentZZ' }
			})
		);
		expect(serialized()).not.toContain('ZZuseragentZZ');
	});

	/* The network origin never exceeds what the store was told to keep. */
	it('reports the origin as not-captured when capture is omitted', async () => {
		ApplicationConfig['errorStore.originCaptureLevel'] = 'omitted';
		await provoke(
			'/redact-origin-omitted',
			new Request('http://e.ly/redact-origin-omitted', {
				headers: { 'x-forwarded-for': SENTINELS.address }
			})
		);

		const fault = (capturedEvents()[0].contexts as Record<string, unknown>)
			.fault as Record<string, unknown>;
		expect(fault.origin).toBe('not-captured');
		expect(serialized()).not.toContain(SENTINELS.address);
	});

	it('does not carry the raw address when capture is anonymized', async () => {
		await provoke(
			'/redact-origin-anon',
			new Request('http://e.ly/redact-origin-anon', {
				headers: { 'x-forwarded-for': SENTINELS.address }
			})
		);

		const fault = (capturedEvents()[0].contexts as Record<string, unknown>)
			.fault as Record<string, unknown>;
		expect(fault.origin).toBeTruthy();
		expect(fault.origin).not.toBe(SENTINELS.address);
		expect(serialized()).not.toContain(SENTINELS.address);
	});

	it('carries the address only when capture is full', async () => {
		ApplicationConfig['errorStore.originCaptureLevel'] = 'full';
		await provoke(
			'/redact-origin-full',
			new Request('http://e.ly/redact-origin-full', {
				headers: { 'x-forwarded-for': SENTINELS.address }
			})
		);

		const fault = (capturedEvents()[0].contexts as Record<string, unknown>)
			.fault as Record<string, unknown>;
		expect(fault.origin).toBe(SENTINELS.address);
	});

	/*
	 * The credential is absent from the event, which is what the requirement is about.
	 *
	 * It is *not* absent from the envelope header, and cannot be: the header's `trace.public_key` is
	 * the DSN's public half, and it is how Sentry routes an envelope to the right project — addressing
	 * information, sent only to the endpoint that already issued it. Asserting it away would be
	 * asserting the protocol away. The secret half of a DSN is never transmitted at all.
	 */
	it('never carries the ingestion credential in the event payload', async () => {
		await provoke('/redact-dsn', new Request('http://e.ly/redact-dsn'));
		const [event] = capturedEvents();
		expect(JSON.stringify(event)).not.toContain('publickey');
		expect(JSON.stringify(event)).not.toContain('o0.ingest.invalid');
	});

	/*
	 * The projection cannot produce a forbidden key today, so this must stay at zero. If it ever moves,
	 * something upstream started adding fields and the refusal branch is the only thing standing
	 * between that and a third party.
	 */
	it('refuses nothing, because nothing unpermitted is ever built', async () => {
		await provoke('/redact-refuse', new Request('http://e.ly/redact-refuse'));
		expect(refusedCount()).toBe(0);
	});

	/* The route pattern is what identifies the endpoint, never a concrete path with an id in it. */
	it('identifies the endpoint by route pattern, not by requested path', async () => {
		const app = new Elysia()
			.onError(errorHandler)
			.get('/redact-pattern/:id', () => {
				throw new Error('deliberate fault');
			});
		await app.handle(new Request('http://e.ly/redact-pattern/ZZobjectidZZ'));
		await flushForTest();
		await flushSentry();

		const tags = capturedEvents()[0].tags as Record<string, string>;
		expect(tags.route).toBe('/redact-pattern/:id');
		expect(serialized()).not.toContain('ZZobjectidZZ');
	});

	/*
	 * The code location is now sent, so these three assertions are the ones standing between "we tell
	 * an operator where it broke" and "we told a third party what a caller posted".
	 *
	 * A stack is the vehicle, because a stack's first line is the error message and an interpolated
	 * message is the likeliest way a token or a secret reaches a diagnostic record by accident. The
	 * store never keeps one; this proves none was reconstructed on the way out either.
	 */
	it('carries a code location but never a stack', async () => {
		await provoke('/redact-frames', new Request('http://e.ly/redact-frames'));
		const [event] = capturedEvents();
		const fault = (event.contexts as Record<string, Record<string, unknown>>)
			.fault;

		expect(fault.codeLocation).toBeDefined();

		/*
		 * `source.ts:line:col` is a frame's signature, and nothing this server sends carries a column —
		 * the projected location has a line and stops there. Matching on it catches a stack arriving by
		 * any route: a raw `error.stack`, a serialized Error, a frame string assembled here.
		 *
		 * Anchored on the file extension rather than on `:\d+:\d+` alone, which a bare time of day
		 * satisfies — the envelope header's own `sent_at` contains `19:34:19`.
		 */
		expect(serialized()).not.toMatch(/\.[cm]?[jt]s:\d+:\d+/);
		expect(serialized()).not.toContain('deliberate fault\n');
	});

	/*
	 * The message is permitted and the location is permitted; the message inside the location is not.
	 * That is the one combination that would mean the parser had stopped stripping it, and it would be
	 * invisible from the outside — the event would look conformant and read plausibly.
	 */
	it('never carries the fault message inside the code location', async () => {
		const app = new Elysia()
			.onError(errorHandler)
			.get('/redact-in-frame', () => {
				throw new Error(`fault touching ${SENTINELS.password}`);
			});
		await app.handle(new Request('http://e.ly/redact-in-frame'));
		await flushForTest();
		await flushSentry();

		const [event] = capturedEvents();
		const fault = (event.contexts as Record<string, Record<string, unknown>>)
			.fault;
		expect(JSON.stringify(fault.codeLocation)).not.toContain(
			SENTINELS.password
		);
		expect(JSON.stringify(fault.codeLocation)).not.toContain('fault touching');
	});

	/*
	 * Tags are what an operator filters on, which makes them the one place unbounded cardinality
	 * actually costs something. Every value here must come from the route pattern, the classification,
	 * the code location, the reference or the client — never from request content.
	 */
	it('carries no request value in any searchable tag', async () => {
		const app = new Elysia()
			.onError(errorHandler)
			.get('/redact-tags/:id', () => {
				throw new Error(`deliberate fault for ${SENTINELS.state}`);
			});
		await app.handle(
			new Request(
				`http://e.ly/redact-tags/ZZtagpathZZ?state=${SENTINELS.state}`
			)
		);
		await flushForTest();
		await flushSentry();

		const tags = capturedEvents()[0].tags as Record<string, string>;
		const values = JSON.stringify(Object.values(tags));
		expect(values).not.toContain('ZZtagpathZZ');
		expect(values).not.toContain(SENTINELS.state);
		/* The message may vary per occurrence, so it must not have reached a tag either. */
		expect(values).not.toContain('deliberate fault');
	});
});
