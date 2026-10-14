/*
 * The protocol does not change language: what a client reads is the same whatever the person's language is.
 */

import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, { encodeParams } from '../test_helper.js';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { ISSUER } from 'lib/configs/env.js';
import { elysia } from 'lib/index.ts';

const RUSSIAN = { 'accept-language': 'ru-RU,ru;q=0.9', cookie: '_lang=ru' };
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };

/* Requests a client or a browser sends; each is sent twice, once with every language signal set. */
const REQUESTS: Array<[string, (extra: Record<string, string>) => Request]> = [
	[
		'an authorization error redirected to the client',
		(extra) =>
			new Request(
				`${ISSUER}/auth?${encodeParams({
					...new AuthorizationRequest({
						client_id: 'i18n-app',
						scope: 'openid',
						state: 'fixed-state'
					}).params,
					prompt: 'none',
					...('ui_locales' in extra ? { ui_locales: 'zh-Hans' } : {})
				})}`,
				{ headers: extra }
			)
	],
	[
		'a token request with an unknown code',
		(extra) =>
			new Request(`${ISSUER}/token`, {
				method: 'POST',
				headers: { ...FORM, ...extra },
				body: new URLSearchParams({
					grant_type: 'authorization_code',
					code: 'nonsense',
					client_id: 'i18n-app',
					redirect_uri: 'https://notes.acme.test/cb',
					code_verifier: 'x'.repeat(43)
				})
			})
	],
	[
		'an introspection request without credentials',
		(extra) =>
			new Request(`${ISSUER}/token/introspect`, {
				method: 'POST',
				headers: { ...FORM, ...extra },
				body: new URLSearchParams({ token: 'nonsense' })
			})
	],
	[
		'a revocation request without credentials',
		(extra) =>
			new Request(`${ISSUER}/token/revocation`, {
				method: 'POST',
				headers: { ...FORM, ...extra },
				body: new URLSearchParams({ token: 'nonsense' })
			})
	],
	[
		'a userinfo request without a token',
		(extra) => new Request(`${ISSUER}/me`, { headers: extra })
	],
	[
		'a pushed request for an unknown client',
		(extra) =>
			new Request(`${ISSUER}/par`, {
				method: 'POST',
				headers: { ...FORM, ...extra },
				body: new URLSearchParams({
					client_id: 'nobody',
					response_type: 'code',
					redirect_uri: 'https://notes.acme.test/cb',
					ui_locales: 'ru'
				})
			})
	],
	[
		'a device authorization for an unknown client',
		(extra) =>
			new Request(`${ISSUER}/device/auth`, {
				method: 'POST',
				headers: { ...FORM, ...extra },
				body: new URLSearchParams({ client_id: 'nobody', scope: 'openid' })
			})
	]
];

async function observed(request: Request) {
	const response = await elysia.handle(request);
	return {
		status: response.status,
		location: response.headers.get('location'),
		contentLanguage: response.headers.get('content-language'),
		body: await response.text()
	};
}

/**
 * @proves A client reads the same protocol answer — status, `error`, `error_description`, body — whatever
 * language the person's browser, cookie or the request itself asks for, and no protocol answer claims a
 * language (RFC 6749 §4.1.2.1 keeps `error_description` ASCII and untranslated).
 */
describe('protocol answers under every language signal', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	for (const [name, build] of REQUESTS) {
		it(`is byte-identical for ${name}`, async () => {
			const plain = await observed(build({}));
			const russian = await observed(
				build({ ...RUSSIAN, ui_locales: 'zh-Hans' })
			);

			expect(russian).toEqual(plain);
			expect(plain.contentLanguage).toBeNull();
		});
	}
});
