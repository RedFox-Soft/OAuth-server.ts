import {
	afterEach,
	beforeAll,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import { admin } from '../provisioning/helpers.ts';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { getActivityStore } from 'lib/adapters/index.ts';
import { dayOf } from 'lib/activity/periods.ts';
import {
	checkApp,
	createApp,
	setRules,
	signInThrough,
	world,
	type AppView,
	type World
} from '../behind_proxy/helpers.ts';
import { person, project } from './helpers.ts';

const DAY = 24 * 60 * 60 * 1000;

interface ListAnswer {
	users: {
		email: string;
		lastActive: { day: string } | { month: string } | null;
	}[];
	activeSince: string | null;
}

async function list(
	cookie: string,
	bucketId: string,
	lastActive?: string
): Promise<ListAnswer> {
	const query = lastActive ? `?lastActive=${lastActive}` : '';
	const reply = await admin(
		'GET',
		`/admin/api/projects/${bucketId}/users${query}`,
		cookie
	);
	expect(reply.status).toBe(200);
	return reply.body as ListAnswer;
}

function emails(answer: ListAnswer): string[] {
	return answer.users.map((user) => user.email).sort();
}

/**
 * @proves The list of people says when each was last active and filters on it: within 7 or 30 days, or not within 30
 * or 90, from the marks a sign-in, a renewal or a request the proxy let through leaves; nobody is called inactive by
 * rounding, and nothing recorded reads as nothing since counting began, never "never".
 */
describe('when people were last active, on the list of people', () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		cookie = await adminCookie();
	});

	it('returns exactly the people each Last active filter names', async () => {
		const bucketId = await project();
		const now = Date.now();
		const [anna, bob, carl, dave] = await Promise.all(
			[0, 1, 2, 3].map(() => person(bucketId))
		);
		const store = getActivityStore();
		await store.mark({
			bucketId,
			accountId: anna.accountId,
			kind: 'local',
			provisioned: false,
			at: new Date(now)
		});
		await store.mark({
			bucketId,
			accountId: bob.accountId,
			kind: 'renewal',
			provisioned: false,
			at: new Date(now - 35 * DAY)
		});
		await store.mark({
			bucketId,
			accountId: carl.accountId,
			kind: 'local',
			provisioned: false,
			at: new Date(now - 130 * DAY)
		});

		expect({
			in7: emails(await list(cookie, bucketId, 'in7')),
			in30: emails(await list(cookie, bucketId, 'in30')),
			not30: emails(await list(cookie, bucketId, 'not30')),
			not90: emails(await list(cookie, bucketId, 'not90'))
		}).toEqual({
			in7: [anna.email],
			in30: [anna.email],
			not30: [bob.email, carl.email, dave.email].sort(),
			not90: [carl.email, dave.email].sort()
		});

		const all = await list(cookie, bucketId);
		const byEmail = new Map(
			all.users.map((user) => [user.email, user.lastActive])
		);
		expect({
			anna: byEmail.get(anna.email),
			bob: byEmail.get(bob.email),
			carl: byEmail.get(carl.email),
			dave: byEmail.get(dave.email),
			activeSince: typeof all.activeSince
		}).toEqual({
			anna: { day: dayOf(new Date(now)) },
			bob: { day: dayOf(new Date(now - 35 * DAY)) },
			carl: { month: dayOf(new Date(now - 130 * DAY)).slice(0, 7) },
			dave: null,
			activeSince: 'string'
		});
	});

	it('refuses a Last active value it does not know', async () => {
		const bucketId = await project();
		const reply = await admin(
			'GET',
			`/admin/api/projects/${bucketId}/users?lastActive=yesterday`,
			cookie
		);
		expect(reply.status).toBe(422);
	});
});

/**
 * @proves A person working on an app behind the proxy on a session they opened days ago is active today: the request
 * the proxy let through marks them, so the list of people and monthly active people count them.
 */
describe('a person let through by the proxy is active', () => {
	let w: World;
	let app: AppView;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
	});

	afterEach(() => {
		setSystemTime();
	});

	it('marks a person working on an open app session as active today', async () => {
		app = await createApp(w.cookie, w.acme.id, {
			rootGroups: [w.acme.staff],
			name: 'Wiki'
		});
		await setRules(w.cookie, w.acme.id, app.id, [
			{ path: '/', who: { kind: 'groups', groups: [w.acme.staff] } }
		]);
		const target = { slug: w.acme.slug, app };
		const signed = await signInThrough(target, w.acme.staffMember);

		const later = Date.now() + 3 * DAY;
		setSystemTime(new Date(later));
		const allowed = await checkApp(target, {
			uri: '/pages/home',
			cookie: signed.cookie
		});
		expect(allowed.status).toBe(200);
		await new Promise((resolve) => setTimeout(resolve, 20));

		const counted = await getActivityStore().count(
			w.acme.id,
			dayOf(new Date(later)),
			new Date(later)
		);
		const fresh = await adminCookie();
		const answer = await list(fresh, w.acme.id, 'in7');
		expect({
			countedToday: counted.total,
			listed: answer.users
				.filter((user) => user.email === w.acme.staffMember.email)
				.map((user) => user.lastActive)
		}).toEqual({
			countedToday: 1,
			listed: [{ day: dayOf(new Date(later)) }]
		});
	});
});
