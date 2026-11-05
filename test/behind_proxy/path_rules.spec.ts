import { beforeAll, describe, expect, it, setSystemTime } from 'bun:test';

import bootstrap from '../test_helper.js';
import { admin } from '../provisioning/helpers.ts';
import { DECISION_TABLE, decisionRules, type Role } from './decision_table.ts';
import {
	checkApp,
	createApp,
	expectStatus,
	group,
	member,
	setRules,
	signInThrough,
	world,
	type AppView,
	type World
} from './helpers.ts';

/* Set up once, on first use, so a case that needs it fails with the reason the setup failed. */
function once<T>(make: () => Promise<T>): () => Promise<T> {
	let made: Promise<T> | undefined;
	return () => (made ??= make());
}

/* Not a page navigation, so a request with no session is answered `401` rather than sent to sign-in. */
const API = 'application/json';

const STATUS = { allow: 200, sign_in: 401, deny: 403 } as const;

/**
 * @proves The rules of an app behind a proxy decide the live check exactly as written: the most specific rule wins
 * however the path is spelled, a path the app might read differently is refused outright, a public rule lets
 * through only reads of its own path (or its subtree when it says so), and a group deleted after a rule named it
 * lets nobody in.
 */
describe('the rules of an app behind a proxy, at the check', () => {
	let w: World;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
	});

	describe('with the root open to Staff, /admin to Admins and /health public', () => {
		const setup = once(async () => {
			const app = await createApp(w.cookie, w.acme.id, {
				rootGroups: [w.acme.staff]
			});
			const { rules } = await setRules(
				w.cookie,
				w.acme.id,
				app.id,
				decisionRules({ staff: w.acme.staff, admins: w.acme.admins }).map(
					({ path, who }) => ({
						path,
						who:
							who.kind === 'groups'
								? { kind: 'groups' as const, groups: who.groupIds }
								: who
					})
				)
			);
			expect(rules.map((rule) => rule.path)).toEqual([
				'/',
				'/admin',
				'/health'
			]);
			const target = { slug: w.acme.slug, app };
			const cookies: Record<Role, string | undefined> = {
				none: undefined,
				staff: (await signInThrough(target, w.acme.staffMember)).cookie,
				admins: (await signInThrough(target, w.acme.adminMember)).cookie
			};
			return { target, cookies };
		});

		it.each(
			DECISION_TABLE.map((row) => [row.method, row.rawPath, row.person, row])
		)(
			'the most specific rule decides %s %s for %s',
			async (method, rawPath, person, row) => {
				const { target, cookies } = await setup();

				const res = await checkApp(target, {
					method,
					uri: rawPath,
					cookie: cookies[person],
					accept: API
				});

				expect({
					status: res.status,
					reason: res.headers.get('x-auth-reason')
				}).toEqual({ status: STATUS[row.outcome], reason: row.reason });
			}
		);

		it.each([['/Admin/users'], ['/admin/../admin/users'], ['//admin/users']])(
			'a path that differs from /admin only in case, dot segments or doubled slashes is decided by /admin: %s',
			async (uri) => {
				const { target, cookies } = await setup();

				const res = await checkApp(target, {
					uri,
					cookie: cookies.staff,
					accept: API
				});

				expect(res.status).toBe(403);
				expect(res.headers.get('x-auth-reason')).toBe('not_in_group');
			}
		);

		it.each([
			['GET', '/health', 200],
			['HEAD', '/health', 200],
			['POST', '/health', 401],
			['GET', '/health/details', 401],
			['GET', '/Health', 401]
		] as [string, string, number][])(
			'only GET and HEAD of exactly /health, in that letter case, pass without a session: %s %s',
			async (method, uri, status) => {
				const { target } = await setup();

				const res = await checkApp(target, { method, uri, accept: API });

				expect(res.status).toBe(status);
			}
		);
	});

	describe('with every path public', () => {
		const setup = once(async () => {
			const app = await createApp(w.cookie, w.acme.id, {
				rootGroups: [w.acme.staff]
			});
			await setRules(w.cookie, w.acme.id, app.id, [
				{ path: '/', who: { kind: 'public', subtree: true } }
			]);
			return { slug: w.acme.slug, app };
		});

		it.each([
			['an encoded slash', '/admin%2Fusers'],
			['an encoded backslash', '/admin%5cusers'],
			['a backslash', '/admin\\users'],
			['a semicolon', '/admin;jsessionid=x/users'],
			['an encoded NUL', '/admin%00/users'],
			['an encoded dot segment', '/x/%2e%2e/admin'],
			['no leading slash', 'admin/users']
		])(
			'an ambiguous path is refused without consulting any rule: %s',
			async (_what, uri) => {
				const target = await setup();

				const res = await checkApp(target, { uri, accept: API });

				expect(res.status).toBe(403);
				expect(res.headers.get('x-auth-reason')).toBe('ambiguous_path');
			}
		);
	});

	describe('with every path public, a path the check reserves for itself', () => {
		it.each([
			['/_foxauth/admin'],
			['/_FOXAUTH/callback'],
			['/x/../_foxauth/other']
		])(
			'is answered by the check and never passed to the app: %s',
			async (uri) => {
				const app = await createApp(w.cookie, w.acme.id, {
					rootGroups: [w.acme.staff]
				});
				await setRules(w.cookie, w.acme.id, app.id, [
					{ path: '/', who: { kind: 'public', subtree: true } }
				]);

				const res = await checkApp({ slug: w.acme.slug, app }, { uri });

				expect(res.status).toBe(404);
				expect(res.headers.get('x-auth-reason')).toBe('reserved_path');
			}
		);
	});

	describe('with /docs public together with everything under it', () => {
		it('a GET under /docs passes without a session', async () => {
			const app: AppView = await createApp(w.cookie, w.acme.id, {
				rootGroups: [w.acme.staff]
			});
			await setRules(w.cookie, w.acme.id, app.id, [
				{ path: '/', who: { kind: 'groups', groups: [w.acme.staff] } },
				{ path: '/docs', who: { kind: 'public', subtree: true } }
			]);

			const res = await checkApp(
				{ slug: w.acme.slug, app },
				{ uri: '/docs/guide/intro?lang=en', accept: API }
			);

			expect(res.status).toBe(200);
			expect(res.headers.get('x-auth-reason')).toBe('public');
		});
	});

	describe('a rule naming a group that is then deleted', () => {
		it('the deleted group admits no one', async () => {
			const reporters = await group(w.acme.id, 'Reporters');
			const reporter = await member(w.acme, [reporters]);
			const app = await createApp(w.cookie, w.acme.id, {
				rootGroups: [w.acme.staff]
			});
			await setRules(w.cookie, w.acme.id, app.id, [
				{ path: '/', who: { kind: 'project' } },
				{ path: '/reports', who: { kind: 'groups', groups: [reporters] } }
			]);
			const target = { slug: w.acme.slug, app };
			const { cookie } = await signInThrough(target, reporter);
			expect(
				(await checkApp(target, { uri: '/reports/q3', cookie })).status
			).toBe(200);
			expectStatus(
				await admin(
					'DELETE',
					`/admin/api/projects/${w.acme.id}/groups/${reporters}`,
					w.cookie
				),
				204,
				'deleting the group'
			);
			/* Past the minute a person's groups are kept for. */
			setSystemTime(new Date(Date.now() + 61_000));

			try {
				const res = await checkApp(target, {
					uri: '/reports/q3',
					cookie,
					accept: API
				});

				expect(res.status).toBe(403);
				expect(res.headers.get('x-auth-reason')).toBe('not_in_group');
			} finally {
				setSystemTime();
			}
		});
	});
});
