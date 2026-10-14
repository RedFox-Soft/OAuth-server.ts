/*
 * No value of any language signal can break a sign-in or reach the page.
 */

import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, { encodeParams } from '../test_helper.js';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { withCookies } from '../consent_page/flow.ts';
import { ISSUER } from 'lib/configs/env.js';
import { elysia } from 'lib/index.ts';
import { SUPPORTED_LANGUAGES } from 'lib/i18n/languages.ts';

const MARK = 'qz7mark';

/* A small seeded generator, so a failure names the same input on every run. */
function generator(seed: number) {
	let state = seed;
	return () => {
		state = (state * 1103515245 + 12345) % 2 ** 31;
		return state / 2 ** 31;
	};
}

const PIECES = [
	'ru',
	'RU-ru',
	'zh',
	'zh-TW',
	'zh-Hant-HK',
	'en_US',
	'*',
	'',
	';q=0',
	';q=1.5',
	';q=abc',
	',',
	' ',
	'x-private',
	'i-default',
	'\u0007',
	'%00',
	'<script>',
	'"',
	"'",
	'é',
	'中文',
	'a'.repeat(40)
];

function values(seed: number, count: number): string[] {
	const random = generator(seed);
	const out: string[] = [];
	for (let i = 0; i < count; i++) {
		const length = 1 + Math.floor(random() * 12);
		const parts = [`${MARK}${i}`];
		for (let j = 0; j < length; j++) {
			parts.push(PIECES[Math.floor(random() * PIECES.length)] ?? '');
		}
		// Every tenth value is enormous: a header of thousands of ranges must cost no more than a short one.
		out.push(i % 10 === 0 ? parts.join(',').repeat(60) : parts.join(','));
	}
	return out;
}

async function signInPage(query: Record<string, unknown>, headers: Headers) {
	const started = await elysia.handle(
		new Request(`${ISSUER}/auth?${encodeParams(query)}`, { headers })
	);
	const location = started.headers.get('location') ?? '';
	const page = await elysia.handle(
		new Request(`${ISSUER}${location}`, {
			headers: { cookie: withCookies(headers.get('cookie') ?? '', started) }
		})
	);
	return { started, page, html: await page.clone().text() };
}

function query(extra: Record<string, string> = {}) {
	return new AuthorizationRequest({
		client_id: 'i18n-app',
		scope: 'openid',
		...extra
	}).params;
}

function expectUnharmed(
	result: Awaited<ReturnType<typeof signInPage>>,
	value: string
) {
	const marker = value.slice(0, value.indexOf(',') >>> 0) || MARK;
	expect(result.started.status).toBe(303);
	expect(result.page.status).toBe(200);
	const lang = /<html lang="([^"]+)"/.exec(result.html)?.[1];
	expect(SUPPORTED_LANGUAGES as readonly string[]).toContain(lang ?? '');
	expect(result.html).not.toContain(marker);
	for (const response of [result.started, result.page]) {
		for (const [, header] of response.headers) {
			expect(header).not.toContain(marker);
		}
	}
}

/**
 * @proves Whatever an attacker or a broken client puts in `ui_locales`, `Accept-Language` or the language
 * cookie, the sign-in still starts, the page declares one of the three languages, and the submitted value is
 * never echoed back in the page or its headers.
 */
describe('language signals the server cannot use', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('never break a sign-in or reach the page when sent as ui_locales', async () => {
		for (const value of values(1, 70)) {
			expectUnharmed(
				await signInPage(query({ ui_locales: value }), new Headers()),
				value
			);
		}
	});

	it('never break a sign-in or reach the page when sent as Accept-Language', async () => {
		for (const value of values(2, 70)) {
			const headers = new Headers();
			// A header value is Latin-1 without control characters; a browser cannot send anything else.
			const sendable = Array.from(value)
				.filter((c) => c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 255)
				.join('');
			headers.set('accept-language', sendable);
			expectUnharmed(await signInPage(query(), headers), value);
		}
	});

	it('never break a sign-in or reach the page when sent as the language cookie', async () => {
		for (const value of values(3, 70)) {
			const headers = new Headers();
			headers.set(
				'cookie',
				`_lang=${encodeURIComponent(value).replace(/%2C/g, ',')}`
			);
			expectUnharmed(await signInPage(query(), headers), value);
		}
	});
});
