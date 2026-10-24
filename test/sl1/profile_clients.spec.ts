import { describe, it, expect, beforeAll } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { shaped } from 'test/shape.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { send } from '../feature_gate/helpers.ts';
import { superAdminCookie } from '../settings_apply/helpers.ts';
import { INITIAL_ACCESS_TOKEN } from './profile.config.ts';

const ErrorBody = Type.Object({
	error: Type.String(),
	error_description: Type.Optional(Type.String())
});

function register(body: Record<string, unknown>, token?: string) {
	return send('/reg', {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			...(token ? { authorization: `Bearer ${token}` } : {})
		},
		body: JSON.stringify(body)
	});
}

function signIn(parameters: Record<string, string>) {
	return new AuthorizationRequest({
		scope: 'openid',
		...parameters
	}).authorize();
}

function accepted(res: Response) {
	expect(res.status).toBe(303);
	expect(res.headers.get('location')).toContain('/ui/');
}

/**
 * @proves Under the IPSIE SL1 profile an application reaches the server only through an `https` or private-use
 * redirect it registered beforehand, with the code flow, and only when it was registered by an administrator or with
 * an initial access token.
 */
describe('applications under the IPSIE SL1 profile', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'profile' });
		await ensureAdminSeed();
	});

	describe('an http redirect URI', () => {
		it('is refused at dynamic registration, loopback included', async () => {
			const res = await register(
				{
					redirect_uris: ['http://127.0.0.1/cb'],
					application_type: 'native',
					token_endpoint_auth_method: 'none'
				},
				INITIAL_ACCESS_TOKEN
			);

			expect(res.status).toBe(400);
			expect(shaped(ErrorBody, await res.json()).error).toBe(
				'invalid_redirect_uri'
			);
		});

		it('is refused when an administrator creates an application with one', async () => {
			const res = await send(
				`/admin/api/projects/${DEFAULT_BUCKET_ID}/clients`,
				{
					method: 'POST',
					headers: {
						cookie: await superAdminCookie(),
						'content-type': 'application/json'
					},
					body: JSON.stringify({
						clientName: 'Loopback CLI',
						grantTypes: ['authorization_code'],
						redirectUris: ['http://127.0.0.1/cb'],
						tokenEndpointAuthMethod: 'none'
					})
				}
			);

			expect(res.status).toBe(422);
		});

		it('is refused at the authorization endpoint when a stored application names it', async () => {
			const res = await signIn({ client_id: 'sl1-loopback' });

			expect(res.status).toBe(400);
			expect(await res.text()).toContain('redirect_uri');
		});

		it('is refused as the place to return to after signing out', async () => {
			const res = await send(
				`/logout?client_id=sl1-loopback&post_logout_redirect_uri=${encodeURIComponent('http://127.0.0.1/bye')}`,
				{ method: 'GET' }
			);

			expect(res.status).toBe(400);
			expect(await res.text()).toContain('invalid_request');
		});
	});

	it('accepts a native application returning to a private-use scheme', async () => {
		accepted(await signIn({ client_id: 'sl1-native' }));
	});

	it('accepts a web application returning to an https address', async () => {
		accepted(await signIn({ client_id: 'sl1-web' }));
	});

	it('refuses dynamic registration without the initial access token', async () => {
		const res = await register({
			redirect_uris: ['https://anon.example.com/cb']
		});

		expect(res.status).toBe(400);
		expect(shaped(ErrorBody, await res.json()).error).toBe('invalid_request');
	});

	it('refuses response_type=none even for an application registered for it', async () => {
		const res = await signIn({ client_id: 'sl1-none', response_type: 'none' });

		expect(res.headers.get('location')).toContain(
			'error=unsupported_response_type'
		);
	});

	it('still answers a project account page asking with response_type=none', async () => {
		const res = await signIn({
			client_id: `account.${DEFAULT_BUCKET_ID}`,
			response_type: 'none',
			redirect_uri: 'http://localhost:3000/account/apps/callback'
		});

		expect(res.headers.get('location') ?? '').not.toContain(
			'unsupported_response_type'
		);
	});
});
