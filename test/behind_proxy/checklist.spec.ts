import {
	afterEach,
	beforeAll,
	describe,
	expect,
	it,
	setSystemTime,
	spyOn
} from 'bun:test';
import { Type, type Static } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { getBehindProxyAppStore, getBucketStore } from 'lib/adapters/index.ts';
import { whenUsageRecorded } from 'lib/behind_proxy/usage.ts';
import { admin } from '../provisioning/helpers.ts';
import { shaped } from '../shape.ts';
import {
	behindProxyPath,
	checkApp,
	createApp,
	expectStatus,
	project,
	signInThrough,
	world,
	type AppView,
	type World
} from './helpers.ts';

/* What the Connect page reads of an app: its checklist, the hosts its proxy reported wrongly, whether sign-ups are open. */
const Connect = Type.Object({
	checklist: Type.Object({
		createdAt: Type.String(),
		firstAskedAt: Type.Union([Type.String(), Type.Null()]),
		firstSignInAt: Type.Union([Type.String(), Type.Null()]),
		firstAllowedAt: Type.Union([Type.String(), Type.Null()])
	}),
	lastAskedAt: Type.Union([Type.String(), Type.Null()]),
	mismatchedHosts: Type.Array(Type.String()),
	signUpsOpen: Type.Boolean()
});
type Connect = Static<typeof Connect>;

/**
 * @proves The Connect page tells an administrator how far an app behind a proxy has got — the proxy asked, someone
 * signed in through it, someone got through — each marked once, at the time it first happened; names a host the
 * proxy reported that is not the app's address; says when "Everyone in the project" lets in anyone who signs up;
 * and a flood of checks costs the datastore at most one write a minute for the app.
 */
describe('an app behind a proxy, as its Connect page reads it', () => {
	let w: World;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
	});

	afterEach(() => {
		setSystemTime();
	});

	async function connectOf(bucketId: string, app: AppView): Promise<Connect> {
		await whenUsageRecorded();
		const reply = await admin(
			'GET',
			behindProxyPath(bucketId, app.id),
			w.cookie
		);
		expectStatus(reply, 200, 'reading an app behind the proxy');
		return shaped(Connect, reply.body);
	}

	describe('a new app', () => {
		it('the first check, first sign-in and first allowed request each mark their checklist step once', async () => {
			const app = await createApp(w.cookie, w.acme.id, {
				rootGroups: [w.acme.staff]
			});
			const target = { slug: w.acme.slug, app };
			const created = await connectOf(w.acme.id, app);
			expect(created.checklist).toMatchObject({
				firstAskedAt: null,
				firstSignInAt: null,
				firstAllowedAt: null
			});

			await checkApp(target, { uri: '/' });
			const asked = await connectOf(w.acme.id, app);
			expect(asked.checklist.firstAskedAt).not.toBeNull();
			expect(asked.checklist.firstSignInAt).toBeNull();
			expect(asked.checklist.firstAllowedAt).toBeNull();

			const { cookie } = await signInThrough(target, w.acme.staffMember);
			const signedIn = await connectOf(w.acme.id, app);
			expect(signedIn.checklist.firstSignInAt).not.toBeNull();
			expect(signedIn.checklist.firstAllowedAt).toBeNull();

			await checkApp(target, { uri: '/reports', cookie });
			const first = (await connectOf(w.acme.id, app)).checklist;
			expect(first.firstAllowedAt).not.toBeNull();

			// Later, the same three happen again; each step keeps the time it was first reached.
			setSystemTime(new Date(Date.now() + 5 * 60_000));
			const again = await signInThrough(target, w.acme.staffMember);
			await checkApp(target, { uri: '/reports', cookie: again.cookie });
			const later = await connectOf(w.acme.id, app);
			expect(later.checklist).toEqual(first);
			expect(later.lastAskedAt).not.toBe(first.firstAskedAt);
		});
	});

	describe('a proxy that reports another host', () => {
		it('Connect names that host', async () => {
			const app = await createApp(w.cookie, w.acme.id, {
				rootGroups: [w.acme.staff]
			});

			await checkApp(
				{ slug: w.acme.slug, app },
				{ host: 'grafana.internal:3000' }
			);

			const view = await connectOf(w.acme.id, app);
			expect(view.mismatchedHosts).toEqual(['grafana.internal:3000']);
			// A report for the wrong host is not the proxy asking about this app.
			expect(view.checklist.firstAskedAt).toBeNull();
		});
	});

	describe('sign-ups open', () => {
		it('the app shows that "Everyone in the project" lets anyone who signs up in', async () => {
			const app = await createApp(w.cookie, w.open.id, {
				rootGroups: [w.open.staff]
			});

			expect((await connectOf(w.open.id, app)).signUpsOpen).toBe(true);
		});

		it('says nothing of sign-ups for a project where nobody can create an account', async () => {
			const closed = await project('closed');
			await getBucketStore().update(closed.id, { registrationOpen: false });
			const app = await createApp(w.cookie, closed.id, {
				rootGroups: [closed.staff]
			});

			expect((await connectOf(closed.id, app)).signUpsOpen).toBe(false);
		});
	});

	describe('one app', () => {
		it('a burst of checks writes at most one usage record for the app within a minute', async () => {
			const app = await createApp(w.cookie, w.acme.id, {
				rootGroups: [w.acme.staff]
			});
			const noteUsage = spyOn(getBehindProxyAppStore(), 'noteUsage');
			try {
				await Promise.all(
					Array.from({ length: 50 }, () =>
						checkApp({ slug: w.acme.slug, app }, { uri: '/' })
					)
				);
				setSystemTime(new Date(Date.now() + 45_000));
				await checkApp({ slug: w.acme.slug, app }, { uri: '/' });
				await whenUsageRecorded();

				const writes = noteUsage.mock.calls.filter(([id]) => id === app.id);
				expect(writes.length).toBe(1);
			} finally {
				noteUsage.mockRestore();
			}
		});
	});
});
