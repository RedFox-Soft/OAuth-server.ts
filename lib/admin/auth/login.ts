import { Elysia, t } from 'elysia';
import crypto from 'node:crypto';
import { ISSUER } from '../../configs/env.js';
import { getUserStore, adminSessionStore } from '../../adapters/index.js';
import { createAdminSession, sessionCookieAttributes } from './session.js';
import { routeNames } from '../../consts/param_list.js';
import {
	ADMIN_CLIENT_ID,
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE
} from '../consts.js';

const REDIRECT_URI = `${ISSUER}/admin/callback`;

function base64url(buf: Buffer) {
	return buf.toString('base64url');
}

export const adminLogin = new Elysia({ name: 'admin-login' })
	.get('/admin/login', ({ cookie, redirect }) => {
		const verifier = base64url(crypto.randomBytes(32));
		const challenge = base64url(
			crypto.createHash('sha256').update(verifier).digest()
		);
		const state = base64url(crypto.randomBytes(16));
		cookie.admin_oauth.set({
			value: JSON.stringify({ verifier, state }),
			httpOnly: true,
			sameSite: 'lax',
			secure: true,
			path: '/admin',
			maxAge: 600
		});
		const url = new URL(`${ISSUER}${routeNames.authorization}`);
		url.search = new URLSearchParams({
			client_id: ADMIN_CLIENT_ID,
			response_type: 'code',
			redirect_uri: REDIRECT_URI,
			scope: 'openid',
			state,
			code_challenge: challenge,
			code_challenge_method: 'S256'
		}).toString();
		return redirect(url.toString(), 302);
	})
	.get(
		'/admin/callback',
		async ({ query, cookie, redirect, set }) => {
			// Elysia auto-parses JSON-looking cookie values into objects on read,
			// so the stored `{ verifier, state }` may arrive already deserialised.
			const rawSaved = cookie.admin_oauth.value as unknown;
			const saved =
				rawSaved === undefined || rawSaved === null || rawSaved === ''
					? null
					: ((typeof rawSaved === 'string'
							? JSON.parse(rawSaved)
							: rawSaved) as {
							verifier: string;
							state: string;
						});
			cookie.admin_oauth.remove();
			if (!saved || saved.state !== query.state) {
				set.status = 400;
				return { error: 'invalid_state', message: 'state mismatch' };
			}
			const res = await fetch(`${ISSUER}${routeNames.token}`, {
				method: 'POST',
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({
					grant_type: 'authorization_code',
					code: query.code,
					redirect_uri: REDIRECT_URI,
					client_id: ADMIN_CLIENT_ID,
					code_verifier: saved.verifier
				})
			});
			if (!res.ok) {
				set.status = 401;
				return { error: 'token_exchange_failed', message: 'login failed' };
			}
			const tokens = (await res.json()) as {
				access_token: string;
				id_token: string;
				refresh_token?: string;
			};
			// Deliberate first-party BFF shortcut: this id_token was just minted by
			// THIS same server and obtained via the PKCE-bound code exchange above, so
			// we trust it and only base64url-decode the payload to read `sub` — no
			// signature verification. This MUST be replaced with full signature
			// verification (e.g. via the local JWKS) if the token exchange ever
			// becomes cross-origin or the token can originate from an untrusted party.
			const sub = (
				JSON.parse(
					Buffer.from(tokens.id_token.split('.')[1], 'base64url').toString()
				) as { sub: string }
			).sub;
			const user = await getUserStore(ADMIN_BUCKET_ID).find(sub);
			if (!user || !user.active) {
				set.status = 403;
				return { error: 'not_admin', message: 'no admin account' };
			}
			const session = await createAdminSession({
				userId: user._id,
				bucketId: ADMIN_BUCKET_ID,
				tokens: {
					accessToken: tokens.access_token,
					idToken: tokens.id_token,
					refreshToken: tokens.refresh_token
				}
			});
			cookie[ADMIN_SESSION_COOKIE].set({
				value: session._id,
				...sessionCookieAttributes()
			});
			return redirect('/admin', 302);
		},
		{
			// The provider appends `iss` (RFC 9207 authorization-response issuer
			// identifier) to the redirect; the app runs with `normalize: false`, so a
			// strict { code, state } schema would 422 on the extra param. Accept it.
			query: t.Object({
				code: t.String(),
				state: t.String(),
				iss: t.Optional(t.String())
			})
		}
	)
	.post('/admin/api/logout', async ({ cookie }) => {
		const id = cookie[ADMIN_SESSION_COOKIE]?.value as string | undefined;
		if (id) await adminSessionStore.destroy(id);
		cookie[ADMIN_SESSION_COOKIE].remove();
		return { ok: true };
	});
