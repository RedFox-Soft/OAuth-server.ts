import {
	beforeAll,
	describe,
	expect,
	it,
	setSystemTime,
	spyOn
} from 'bun:test';

import bootstrap from '../test_helper.js';
import { getUserStore } from 'lib/adapters/index.ts';
import {
	answerOf,
	check,
	checkApp,
	createApp,
	hostOf,
	project,
	scheduleDeletion,
	setRules,
	signInThrough,
	world,
	type AppView,
	type Forwarded,
	type World
} from './helpers.ts';

/* Set up once, on first use, so a case that needs it fails with the reason the setup failed. */
function once<T>(make: () => Promise<T>): () => Promise<T> {
	let made: Promise<T> | undefined;
	return () => (made ??= make());
}

/**
 * @proves The check a proxy makes answers only about the app it names, at that app's address, for the path and
 * method the proxy really saw: a check that leaves either out is refused rather than read as the root, every way
 * of naming an app this project does not hold gets one indistinguishable refusal, and a fault is never an answer
 * that lets the request through.
 */
describe('the check a proxy makes before passing a request on', () => {
	let w: World;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
	});

	describe('a check', () => {
		const openApp = once(async () => {
			const app = await createApp(w.cookie, w.acme.id, {
				rootGroups: [w.acme.staff]
			});
			await setRules(w.cookie, w.acme.id, app.id, [
				{ path: '/', who: { kind: 'public', subtree: true } }
			]);
			return app;
		});

		it.each([['X-Forwarded-Uri'], ['X-Forwarded-Method']] as [Forwarded][])(
			'a check without the original path or method is refused, never read as /: no %s',
			async (missing) => {
				const app = await openApp();

				const res = await checkApp(
					{ slug: w.acme.slug, app },
					{ omit: [missing] }
				);

				expect(res.status).toBe(403);
				expect(res.headers.get('x-auth-reason')).toBe('missing_forwarded');
			}
		);
	});

	describe('a check for something the project does not hold', () => {
		const apps = once(async () => {
			const acme = await createApp(w.cookie, w.acme.id, {
				rootGroups: [w.acme.staff]
			});
			const beta = await createApp(w.cookie, w.beta.id, {
				rootGroups: [w.beta.staff]
			});
			const doomedProject = await project('doomed');
			const doomed = await createApp(w.cookie, doomedProject.id, {
				rootGroups: [doomedProject.staff]
			});
			await scheduleDeletion(doomedProject.id);
			return { acme, beta, doomed };
		});

		const ways: [
			string,
			(a: Awaited<ReturnType<typeof apps>>) => Promise<Response>
		][] = [
			[
				'an unknown project',
				({ acme }) =>
					check({ slug: 'nowhere', appId: acme.id, host: hostOf(acme.address) })
			],
			[
				'an unknown app',
				({ acme }) =>
					check({
						slug: w.acme.slug,
						appId: 'no-such-app',
						host: hostOf(acme.address)
					})
			],
			[
				"another project's app",
				({ beta }) =>
					check({
						slug: w.acme.slug,
						appId: beta.id,
						host: hostOf(beta.address)
					})
			],
			[
				"a host that is not the app's address",
				({ acme }) =>
					check({
						slug: w.acme.slug,
						appId: acme.id,
						host: 'elsewhere.example.com'
					})
			],
			[
				'a project scheduled for deletion',
				({ doomed }) =>
					check({
						slug: 'doomed',
						appId: doomed.id,
						host: hostOf(doomed.address)
					})
			]
		];

		it.each(ways)('the five refusals are identical: %s', async (_way, send) => {
			const made = await apps();
			const reference = await answerOf(
				await check({
					slug: 'never-a-project',
					appId: made.acme.id,
					host: hostOf(made.acme.address)
				})
			);

			const answer = await answerOf(await send(made));

			expect(answer.status).toBe(403);
			expect(new Headers(answer.headers).get('x-auth-reason')).toBe(
				'not_found'
			);
			expect(answer).toEqual(reference);
		});
	});

	describe('a store that throws during the check', () => {
		it('the answer is a server error, never a success', async () => {
			const app: AppView = await createApp(w.cookie, w.acme.id, {
				rootGroups: [w.acme.staff]
			});
			const target = { slug: w.acme.slug, app };
			const { cookie } = await signInThrough(target, w.acme.staffMember);
			/* Past the standing cache, so the check reads the person afresh. */
			setSystemTime(new Date(Date.now() + 61_000));
			const fault = spyOn(getUserStore(w.acme.id), 'find').mockRejectedValue(
				new Error('the user store is unavailable')
			);

			try {
				const res = await checkApp(target, { uri: '/reports', cookie });

				expect(res.status).toBe(500);
			} finally {
				fault.mockRestore();
				setSystemTime();
			}
		});
	});
});
