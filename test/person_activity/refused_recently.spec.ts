import {
	afterEach,
	beforeAll,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';
import { Type, type Static } from '@sinclair/typebox';

import bootstrap from '../test_helper.ts';
import { admin } from '../provisioning/helpers.ts';
import { shaped } from '../shape.ts';
import {
	behindProxyPath,
	checkApp,
	createApp,
	expectStatus,
	scheduleDeletion,
	setRules,
	signInThrough,
	world,
	type AppView,
	type World
} from '../behind_proxy/helpers.ts';
import { from } from './helpers.ts';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';

let w: World;
let app: AppView;

const RefusalsView = Type.Object({
	asOf: Type.String(),
	accessSavedAt: Type.Union([Type.String(), Type.Null()]),
	cut: Type.Boolean(),
	rows: Type.Array(
		Type.Object({
			accountId: Type.String(),
			email: Type.Union([Type.String(), Type.Null()]),
			outcome: Type.String(),
			outcomeWords: Type.String(),
			reason: Type.String(),
			rule: Type.Union([Type.String(), Type.Null()]),
			tool: Type.Union([Type.String(), Type.Null()]),
			count: Type.Number(),
			lastAt: Type.String()
		})
	)
});
type RefusalsView = Static<typeof RefusalsView>;

const MINUTE = 60 * 1000;

/* The clock moves in these cases; a console session from another time is not one the server accepts. */
async function at(time: number): Promise<void> {
	setSystemTime(new Date(time));
	w.cookie = await adminCookie();
}

function target() {
	return { slug: w.acme.slug, app };
}

/* Staff open the wiki; `/admin` is for Admins. One app per case, so a case never meets another's refusals. */
async function wiki(): Promise<AppView> {
	const created = await createApp(w.cookie, w.acme.id, {
		rootGroups: [w.acme.staff],
		name: 'Wiki'
	});
	await setRules(w.cookie, w.acme.id, created.id, [
		{ path: '/', who: { kind: 'groups', groups: [w.acme.staff] } },
		{ path: '/admin', who: { kind: 'groups', groups: [w.acme.admins] } }
	]);
	return created;
}

async function refusedRecently(): Promise<RefusalsView> {
	await flushPersonActivityNow();
	const reply = await admin(
		'POST',
		`${behindProxyPath(w.acme.id, app.id)}/refusals`,
		w.cookie,
		{}
	);
	expectStatus(reply, 200, 'reading who the app refused');
	return shaped(RefusalsView, reply.body);
}

/**
 * @proves On an app's Access tab an administrator sees who the app refused or asked to sign in again in the last day,
 * newest first, with the reason in fixed words and how many times, a person's two UTC days folded into one line, and
 * where the rules were last saved between those refused before and after; nobody else's app and nothing older.
 */
describe('who an app behind the proxy refused recently', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
		from('203.0.113.9');
	});

	afterEach(() => {
		setSystemTime();
	});

	it('lists who the app refused in the last day, with the save time between', async () => {
		const start = Date.now();
		await at(start);
		app = await wiki();
		const staff = await signInThrough(target(), w.acme.staffMember);
		for (const uri of ['/admin/users', '/admin/groups']) {
			const refused = await checkApp(target(), { uri, cookie: staff.cookie });
			expect(refused.status).toBe(403);
		}

		await at(start + 10 * MINUTE);
		const saved = await setRules(w.cookie, w.acme.id, app.id, [
			{ path: '/', who: { kind: 'groups', groups: [w.acme.admins] } }
		]);
		const savedAt = (saved as { accessSavedAt?: string | null }).accessSavedAt;

		await at(start + 20 * MINUTE);
		const narrowed = await checkApp(target(), {
			uri: '/pages/home',
			cookie: staff.cookie
		});
		expect(narrowed.status).toBe(403);

		const view = await refusedRecently();
		expect(view.accessSavedAt).toBe(savedAt ?? null);
		expect(
			view.rows.map((row) => ({
				email: row.email,
				outcome: row.outcomeWords,
				reason: row.reason,
				count: row.count,
				afterSave: row.lastAt > (view.accessSavedAt ?? '')
			}))
		).toEqual([
			{
				email: w.acme.staffMember.email,
				outcome: 'Refused',
				reason: 'Not in the groups that may open /',
				count: 1,
				afterSave: true
			},
			{
				email: w.acme.staffMember.email,
				outcome: 'Refused',
				reason: 'Not in the groups that may open /admin',
				count: 2,
				afterSave: false
			}
		]);
	});

	it("folds a person's refusals across midnight UTC into one line", async () => {
		const now = new Date();
		const midnight = Date.UTC(
			now.getUTCFullYear(),
			now.getUTCMonth(),
			now.getUTCDate() + 1
		);
		await at(midnight - 5 * MINUTE);
		app = await wiki();
		const staff = await signInThrough(target(), w.acme.staffMember);
		expect(
			(await checkApp(target(), { uri: '/admin', cookie: staff.cookie })).status
		).toBe(403);
		await at(midnight + 5 * MINUTE);
		expect(
			(await checkApp(target(), { uri: '/admin', cookie: staff.cookie })).status
		).toBe(403);

		const view = await refusedRecently();
		expect(view.rows.map((row) => [row.reason, row.count])).toEqual([
			['Not in the groups that may open /admin', 2]
		]);
	});

	it('leaves out refusals older than a day and those of another app', async () => {
		const start = Date.now();
		await at(start - 25 * 60 * MINUTE);
		app = await wiki();
		const other = await wiki();
		const staff = await signInThrough(target(), w.acme.staffMember);
		expect(
			(await checkApp(target(), { uri: '/admin', cookie: staff.cookie })).status
		).toBe(403);
		await at(start);
		const elsewhere = await signInThrough(
			{ slug: w.acme.slug, app: other },
			w.acme.staffMember
		);
		expect(
			(
				await checkApp(
					{ slug: w.acme.slug, app: other },
					{ uri: '/admin', cookie: elsewhere.cookie }
				)
			).status
		).toBe(403);

		const view = await refusedRecently();
		expect(view.rows).toEqual([]);
		expect(view.cut).toBe(false);
	});

	it('still lists who was refused in a project scheduled for deletion', async () => {
		await at(Date.now());
		app = await wiki();
		const staff = await signInThrough(target(), w.acme.staffMember);
		expect(
			(await checkApp(target(), { uri: '/admin', cookie: staff.cookie })).status
		).toBe(403);
		await flushPersonActivityNow();
		await scheduleDeletion(w.acme.id);

		const view = await refusedRecently();
		expect(view.rows.map((row) => row.email)).toEqual([
			w.acme.staffMember.email
		]);
	});
});
