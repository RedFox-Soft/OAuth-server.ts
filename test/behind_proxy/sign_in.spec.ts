import { beforeAll, describe, expect, it } from 'bun:test';
import {
	createLocalJWKSet,
	decodeJwt,
	decodeProtectedHeader,
	jwtVerify
} from 'jose';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { getBucketGroupStore, getUserStore } from 'lib/adapters/index.ts';
import { figureOf, startCounting, thisMonth } from '../activity/fixtures.ts';
import { present, shaped } from '../shape.ts';
import { TestAdapter } from '../models.ts';
import { PASSWORD } from '../connected_apps/helpers.ts';
import { BehindProxySignInPayload } from 'lib/behind_proxy/payloads.ts';
import {
	AppJar,
	checkApp,
	createApp,
	hostOf,
	reachCallback,
	signInThrough,
	world,
	type AppView,
	type World
} from './helpers.ts';

const TokenError = Type.Object({ error: Type.String() });

const Jwks = Type.Object({
	keys: Type.Array(Type.Object({ kid: Type.Optional(Type.String()) }))
});

/**
 * @proves A person who opens an app behind a proxy is sent to the project's own sign-in and comes back to the page
 * they asked for; a member of the app's group is then let through with their identity told to the app, plainly
 * and as a statement signed by the project, while anyone else signed in is shown, in their language, who they are
 * signed in as and how to be someone else — and a request that is not a page is refused rather than redirected.
 */
describe('signing in to an app behind a proxy', () => {
	let w: World;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
	});

	async function staffApp(): Promise<{ slug: string; app: AppView }> {
		const app = await createApp(w.cookie, w.acme.id, {
			rootGroups: [w.acme.staff]
		});
		return { slug: w.acme.slug, app };
	}

	describe('an app whose root is open to Staff', () => {
		it('a page navigation with no session is sent to the project’s sign-in', async () => {
			const target = await staffApp();

			const res = await checkApp(target, { uri: '/reports' });

			expect(res.status).toBe(302);
			const location = new URL(
				present(res.headers.get('location'), 'a sign-in')
			);
			expect(`${location.origin}${location.pathname}`).toBe(
				`${ISSUER}/${w.acme.slug}/auth`
			);
			expect(location.searchParams.get('client_id')).toBe(`proxy.${w.acme.id}`);
			expect(location.searchParams.get('redirect_uri')).toBe(
				`${target.app.address}/_foxauth/callback`
			);
			expect(location.searchParams.get('code_challenge_method')).toBe('S256');
		});
	});

	describe('an app whose root is open to Staff, checked by a proxy that reads statuses only', () => {
		it('a page navigation with no session is answered 401 and starts no sign-in', async () => {
			const target = await staffApp();

			const res = await checkApp(target, { uri: '/reports', mode: 'status' });

			expect(res.status).toBe(401);
			expect(res.headers.get('location')).toBeNull();
			expect(res.headers.getSetCookie()).toEqual([]);
		});
	});

	describe('a sign-in started from /reports?x=1', () => {
		it('the person lands back on /reports?x=1 after signing in', async () => {
			const target = await staffApp();

			const { landedAt } = await signInThrough(target, w.acme.staffMember, {
				from: '/reports?x=1'
			});

			expect(landedAt).toBe(`${target.app.address}/reports?x=1`);
		});
	});

	describe('a Staff member signed in through the app', () => {
		it('the check allows them and names their id, email and group ids', async () => {
			const target = await staffApp();
			const { cookie } = await signInThrough(target, w.acme.staffMember);

			const res = await checkApp(target, { uri: '/reports', cookie });

			expect(res.status).toBe(200);
			expect(res.headers.get('x-auth-reason')).toBe('allowed');
			expect(res.headers.get('x-auth-user')).toBe(w.acme.staffMember.accountId);
			expect(res.headers.get('x-auth-email')).toBe(w.acme.staffMember.email);
			expect(res.headers.get('x-auth-groups')).toBe(w.acme.staff);
		});

		it('the signed statement verifies with the project’s keys, names the app as audience and expires in 60 s', async () => {
			const target = await staffApp();
			const { cookie } = await signInThrough(target, w.acme.staffMember);
			const res = await checkApp(target, { uri: '/reports', cookie });
			const assertion = present(
				res.headers.get('x-auth-assertion'),
				'a signed statement'
			);
			const jwks = shaped(
				Jwks,
				await (
					await elysia.handle(new Request(`${ISSUER}/${w.acme.slug}/jwks`))
				).json()
			);

			const { payload } = await jwtVerify(assertion, createLocalJWKSet(jwks), {
				issuer: `${ISSUER}/${w.acme.slug}`,
				audience: target.app.address
			});

			expect(decodeProtectedHeader(assertion).typ).toBe('foxauth-proxy+jwt');
			expect(payload.sub).toBe(w.acme.staffMember.accountId);
			expect(payload.email).toBe(w.acme.staffMember.email);
			expect(payload.groups).toEqual([w.acme.staff]);
			expect(payload.group_names).toEqual(['Staff']);
			expect(present(payload.exp, 'exp') - present(payload.iat, 'iat')).toBe(
				60
			);
		});
	});

	describe('a person whose email has non-ASCII characters', () => {
		it('is let in, with the email percent-encoded in the header and exact in the signed statement', async () => {
			const target = await staffApp();
			const email = `zoë-${String(Date.now())}@exämple.test`;
			const user = await getUserStore(w.acme.id).create(
				email,
				await Bun.password.hash(PASSWORD),
				true
			);
			await getBucketGroupStore().change(w.acme.staff, {
				add: [user._id],
				remove: []
			});
			const { cookie } = await signInThrough(target, { email });

			const res = await checkApp(target, { uri: '/reports', cookie });

			expect(res.status).toBe(200);
			const header = present(res.headers.get('x-auth-email'), 'an email');
			expect(/^[\x20-\x7e]*$/.test(header)).toBe(true);
			expect(decodeURIComponent(header)).toBe(email);
			const assertion = present(
				res.headers.get('x-auth-assertion'),
				'a signed statement'
			);
			expect(decodeJwt(assertion).email).toBe(email);
		});
	});

	describe('a signed-in person outside Staff', () => {
		it('the check refuses them with a page naming their account and offering another account', async () => {
			const target = await staffApp();
			const { cookie } = await signInThrough(target, w.acme.outsider);

			const res = await checkApp(target, { uri: '/reports', cookie });

			expect(res.status).toBe(403);
			expect(res.headers.get('x-auth-reason')).toBe('not_in_group');
			expect(res.headers.get('content-type')).toContain('text/html');
			const page = await res.text();
			expect(page).toContain(hostOf(target.app.address));
			expect(page).toContain(w.acme.outsider.email);
			expect(page).toContain('href="/_foxauth/sign_out?then=start"');
			expect(page).toContain('not_in_group');
		});
	});

	describe('a refused person whose language is Russian', () => {
		it('the denial page is in Russian', async () => {
			const target = await staffApp();
			const { cookie } = await signInThrough(target, w.acme.adminMember);
			await getUserStore(w.acme.id).update(w.acme.adminMember.accountId, {
				profile: { locale: 'ru' }
			});

			const res = await checkApp(target, { uri: '/', cookie });

			expect(res.status).toBe(403);
			expect(res.headers.get('content-language')).toBe('ru');
			expect(await res.text()).toContain('Войти с другим аккаунтом');
		});
	});

	describe('no session', () => {
		it('a request that is not a navigation is refused as unauthenticated, not redirected', async () => {
			const target = await staffApp();

			const res = await checkApp(target, {
				uri: '/api/reports',
				accept: 'application/json'
			});

			expect(res.status).toBe(401);
			expect(res.headers.get('location')).toBeNull();
			expect(res.headers.get('www-authenticate')).toBe(
				`FoxAuth realm="${target.app.address}"`
			);
		});
	});

	describe('a person signing in through an app', () => {
		it('they count as active in the project this month', async () => {
			await startCounting();
			const target = await staffApp();
			const before = await figureOf(w.acme.id, thisMonth());

			await signInThrough(target, w.acme.staffMember);

			const after = await figureOf(w.acme.id, thisMonth());
			expect(after.total - before.total).toBe(1);
		});
	});

	describe('a person already signed in to the project', () => {
		it('signing in to the app shows no form', async () => {
			const first = await staffApp();
			const second = await staffApp();
			const { browser } = await signInThrough(first, w.acme.staffMember);
			const jar = new AppJar();
			const started = jar.absorb(await checkApp(second, { uri: '/' }));

			const step = await browser.open(
				present(started.headers.get('location'), 'a sign-in')
			);

			expect(new URL(step.url).origin).toBe(second.app.address);
			expect(new URL(step.url).pathname).toBe('/_foxauth/callback');
		});
	});

	describe('a code issued for an app sign-in', () => {
		it('the public token endpoint refuses it with invalid_grant, even with the sign-in’s own verifier', async () => {
			const target = await staffApp();
			const { callback } = await reachCallback(target, w.acme.staffMember);
			const state = present(callback.searchParams.get('state'), 'a state');
			const { codeVerifier } = TestAdapter.for('BehindProxySignIn').syncFindAs(
				BehindProxySignInPayload,
				state
			);

			const res = await elysia.handle(
				new Request(`${ISSUER}/${w.acme.slug}/token`, {
					method: 'POST',
					headers: { 'content-type': 'application/x-www-form-urlencoded' },
					body: new URLSearchParams({
						grant_type: 'authorization_code',
						client_id: `proxy.${w.acme.id}`,
						code: present(callback.searchParams.get('code'), 'a code'),
						redirect_uri: `${target.app.address}/_foxauth/callback`,
						code_verifier: codeVerifier
					}).toString()
				})
			);

			expect(res.status).toBe(400);
			expect(shaped(TokenError, await res.json()).error).toBe('invalid_grant');
		});
	});
});
