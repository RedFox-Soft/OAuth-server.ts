import { beforeAll, describe, expect, it, setSystemTime } from 'bun:test';

import bootstrap from '../test_helper.js';
import { admin, type Reply } from '../provisioning/helpers.ts';
import { extractResetUrl, lastEmail } from '../mail_capture.ts';
import { present } from '../shape.ts';
import { Browser } from '../connected_apps/helpers.ts';
import {
	AppJar,
	answerOf,
	behindProxyPath,
	check,
	checkApp,
	createApp,
	expectStatus,
	hostOf,
	member,
	project,
	readApp,
	scheduleDeletion,
	signInThrough,
	world,
	type AppView,
	type Member,
	type Project,
	type World
} from './helpers.ts';

/* Not a page navigation, so a request with no usable session is answered `401` rather than sent to sign-in. */
const API = 'application/json';

/**
 * @proves Taking a person's access away takes it away at every app behind a proxy too, without waiting for the app
 * session to run out: leaving the only allowed group within a minute; being locked, deactivated, deleted, signed
 * out everywhere or having the password reset at the next request; the app's own sign-out at once; and deleting
 * the app or scheduling its project for deletion for everyone. Moving the app to a new address keeps its people
 * signed in.
 */
describe('taking access to an app behind a proxy away', () => {
	let w: World;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
	});

	/* A new member of Staff, signed in to a new app whose root is open to Staff, and let in once. */
	async function letIn(of: Project = w.acme): Promise<{
		target: { slug: string; app: AppView };
		person: Member;
		cookie: string;
		jar: AppJar;
	}> {
		const person = await member(of, [of.staff]);
		const app = await createApp(w.cookie, of.id, { rootGroups: [of.staff] });
		const target = { slug: of.slug, app };
		const { cookie, jar } = await signInThrough(target, person);
		expect(
			(await checkApp(target, { uri: '/reports', cookie, accept: API })).status
		).toBe(200);
		return { target, person, cookie, jar };
	}

	describe('a person let in', () => {
		it('removing them from the only allowed group refuses them once the 60 s window has passed', async () => {
			const { target, person, cookie } = await letIn();
			expectStatus(
				await admin(
					'DELETE',
					`/admin/api/projects/${w.acme.id}/groups/${w.acme.staff}/members/${person.accountId}`,
					w.cookie
				),
				200,
				'removing the person from Staff'
			);
			setSystemTime(new Date(Date.now() + 61_000));

			try {
				const res = await checkApp(target, {
					uri: '/reports',
					cookie,
					accept: API
				});

				expect(res.status).toBe(403);
				expect(res.headers.get('x-auth-reason')).toBe('not_in_group');
			} finally {
				setSystemTime();
			}
		});

		const users = (uid: string) =>
			`/admin/api/projects/${w.acme.id}/users/${uid}`;
		const revocations: [string, (uid: string) => Promise<Reply>][] = [
			[
				'locking them',
				(uid) =>
					admin('POST', `${users(uid)}/lock`, w.cookie, {
						reason: 'a lost laptop'
					})
			],
			[
				'deactivating them',
				(uid) => admin('PATCH', users(uid), w.cookie, { active: false })
			],
			['deleting them', (uid) => admin('DELETE', users(uid), w.cookie)],
			[
				'signing them out everywhere',
				(uid) => admin('POST', `${users(uid)}/sign-out`, w.cookie)
			]
		];

		it.each(revocations)(
			'%s refuses their next request and ends their app session',
			async (_what, revoke) => {
				const { target, person, cookie } = await letIn();
				const reply = await revoke(person.accountId);
				expect(reply.status).toBeLessThan(300);

				const res = await checkApp(target, {
					uri: '/reports',
					cookie,
					accept: API
				});

				expect(res.status).toBe(401);
				expect(res.headers.get('x-auth-reason')).toBe('no_session');
			}
		);

		it('a password reset ends their app session', async () => {
			const { target, person, cookie } = await letIn();
			const started = await checkApp(target, { uri: '/' });
			const browser = new Browser();
			const login = await browser.open(
				present(started.headers.get('location'), 'a sign-in')
			);
			expect(login.url).toMatch(/\/login$/);
			const asked = await browser.post(
				login.url.replace(/\/login$/, '/forgot-password'),
				{ email: person.email }
			);
			expect(asked.status).toBe(200);
			const link = new URL(
				present(
					extractResetUrl(present(lastEmail(), 'a reset email')),
					'a reset link'
				)
			);
			const reset = await browser.post(link.pathname, {
				token: present(link.searchParams.get('token'), 'a reset token'),
				password: 'a new password for the app',
				confirmPassword: 'a new password for the app'
			});
			expect(reset.status).toBe(200);

			const res = await checkApp(target, {
				uri: '/reports',
				cookie,
				accept: API
			});

			expect(res.status).toBe(401);
			expect(res.headers.get('x-auth-reason')).toBe('no_session');
		});

		it('the app’s sign-out address ends their session and the next navigation is sent to sign-in', async () => {
			const { target, cookie, jar } = await letIn();

			const out = jar.absorb(
				await checkApp(target, {
					uri: '/_foxauth/sign_out',
					cookie: jar.header
				})
			);
			expect(out.status).toBe(302);
			expect(out.headers.get('location')).toBe(`${target.app.address}/`);

			const next = await checkApp(target, { uri: '/', cookie: jar.header });
			expect(next.status).toBe(302);
			expect(present(next.headers.get('location'), 'a sign-in')).toContain(
				'/auth?'
			);
			/* The session itself is gone, not only the browser's cookie for it. */
			const replayed = await checkApp(target, {
				uri: '/reports',
				cookie,
				accept: API
			});
			expect(replayed.headers.get('x-auth-reason')).toBe('no_session');
		});
	});

	describe('an app with people using it', () => {
		it('after deleting the app every check for it is refused', async () => {
			const { target, cookie } = await letIn();
			expectStatus(
				await admin(
					'DELETE',
					behindProxyPath(w.acme.id, target.app.id),
					w.cookie
				),
				204,
				'deleting the app'
			);

			const res = await checkApp(target, { uri: '/reports', cookie });

			expect(res.status).toBe(403);
			expect(res.headers.get('x-auth-reason')).toBe('not_found');
		});
	});

	describe('a project scheduled for deletion', () => {
		it('checks for its apps are refused the same way as for an unknown app', async () => {
			const doomed = await project('doomed2');
			const { target, cookie } = await letIn(doomed);
			await scheduleDeletion(doomed.id);
			const unknown = await answerOf(
				await check({
					slug: w.acme.slug,
					appId: 'no-such-app',
					host: hostOf(target.app.address)
				})
			);

			const res = await answerOf(
				await checkApp(target, { uri: '/reports', cookie })
			);

			expect(res).toEqual(unknown);
		});
	});

	describe('a person signed in through an app', () => {
		it('after the app’s address changes, their session still lets them in at the new address', async () => {
			const { target, cookie } = await letIn();
			const moved = 'https://moved.example.com';
			expectStatus(
				await admin(
					'PATCH',
					behindProxyPath(w.acme.id, target.app.id),
					w.cookie,
					{ address: moved }
				),
				200,
				'moving the app'
			);
			expect((await readApp(w.cookie, w.acme.id, target.app.id)).address).toBe(
				moved
			);

			const res = await checkApp(target, {
				host: hostOf(moved),
				uri: '/reports',
				cookie,
				accept: API
			});

			expect(res.status).toBe(200);
			expect(res.headers.get('x-auth-reason')).toBe('allowed');
		});
	});
});
