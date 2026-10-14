/*
 * An application chooses the language of the sign-in pages with `ui_locales` (OIDC Core §3.1.2.1), however it
 * sends the request.
 */

import * as crypto from 'node:crypto';

import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, { encodeParams, formAgent } from '../test_helper.js';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { withCookies } from '../consent_page/flow.ts';
import * as JWT from 'lib/helpers/jwt.ts';
import { ISSUER } from 'lib/configs/env.js';
import { elysia } from 'lib/index.ts';

const ENGLISH_BROWSER = { 'accept-language': 'en-US,en;q=0.9' };

function langOf(html: string): string | undefined {
	return /<html lang="([^"]+)"/.exec(html)?.[1];
}

/* Sends the browser to `/auth?query` and opens the page it is sent to; answers that page's language. */
async function pageLanguage(
	query: Record<string, unknown>,
	headers: Record<string, string> = ENGLISH_BROWSER
) {
	const started = await elysia.handle(
		new Request(`${ISSUER}/auth?${encodeParams(query)}`, { headers })
	);
	expect(started.status).toBe(303);
	const location = started.headers.get('location') ?? '';
	expect(location).toMatch(/^\/ui\/[^/]+\/login$/);
	const page = await elysia.handle(
		new Request(`${ISSUER}${location}`, {
			headers: { cookie: withCookies('', started) }
		})
	);
	expect(page.status).toBe(200);
	return langOf(await page.text());
}

function request(params: Record<string, string>) {
	return new AuthorizationRequest({
		client_id: 'i18n-app',
		scope: 'openid',
		...params
	}).params;
}

/**
 * @proves A client application that names the language it wants with `ui_locales` gets its sign-in pages in
 * that language — in the query, inside a signed request object or through a pushed request — and a value the
 * server cannot serve never makes the sign-in fail.
 */
describe('the language an application asks for', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('shows Russian to an English browser when the application asks for Russian in the query', async () => {
		expect(await pageLanguage(request({ ui_locales: 'ru' }))).toBe('ru');
	});

	it('shows the first language on the application’s list that the server speaks', async () => {
		expect(
			await pageLanguage(request({ ui_locales: 'fr-CA fr zh-Hans' }))
		).toBe('zh-Hans');
	});

	for (const asked of ['fr', 'xx-!!', 'en_US']) {
		it(`signs in without an error and follows the browser when the application asks for “${asked}”`, async () => {
			expect(
				await pageLanguage(request({ ui_locales: asked }), {
					'accept-language': 'ru'
				})
			).toBe('ru');
		});
	}

	it('shows Russian when the application asks for it inside a signed request object', async () => {
		const verifier = crypto.randomBytes(32).toString('base64url');
		const signed = await JWT.sign(
			{
				client_id: 'i18n-jar',
				redirect_uri: 'https://notes.acme.test/cb',
				response_type: 'code',
				scope: 'openid',
				code_challenge_method: 'S256',
				code_challenge: crypto.hash('sha256', verifier, 'base64url'),
				ui_locales: 'ru'
			},
			Buffer.from('secret'),
			'HS256',
			{ issuer: 'i18n-jar', audience: ISSUER, expiresIn: 30 }
		);

		expect(await pageLanguage({ client_id: 'i18n-jar', request: signed })).toBe(
			'ru'
		);
	});

	it('shows Russian when the application asks for it in a pushed request', async () => {
		const verifier = crypto.randomBytes(32).toString('base64url');
		const { data, error } = await formAgent.par.post({
			client_id: 'i18n-app',
			redirect_uri: 'https://notes.acme.test/cb',
			response_type: 'code',
			scope: 'openid',
			code_challenge_method: 'S256',
			code_challenge: crypto.hash('sha256', verifier, 'base64url'),
			ui_locales: 'ru'
		});
		expect(error).toBeNull();

		expect(
			await pageLanguage({
				client_id: 'i18n-app',
				request_uri: String(data?.request_uri)
			})
		).toBe('ru');
	});
});
