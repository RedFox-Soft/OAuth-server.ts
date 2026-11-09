import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { adapter, adminAuditStore } from 'lib/adapters/index.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';
import {
	clockAt,
	iso,
	listedAddress,
	pass,
	publication,
	resetAttackerList,
	seconds,
	signer
} from './helper.ts';
import {
	attempt,
	PASSWORD,
	person,
	seedProject,
	setGuessing,
	WRONG
} from './door.ts';

let bucketId: string;
let cookie: string;
let undoClock: () => void = () => {};

async function listing(address: string): Promise<void> {
	const foxtrust = await signer();
	await publication().publish({
		version: `a${String(seconds(0))}`,
		builtAt: iso(0),
		validUntil: iso(3),
		lines: [{ network: address, lastSeen: seconds(-1) }],
		by: foxtrust
	});
	expect(await pass(foxtrust)).toBe('accepted');
}

function call(method: string, path: string, body?: unknown): Promise<Response> {
	return elysia.handle(
		new Request(`${ISSUER}${path}`, {
			method,
			headers: {
				cookie,
				...(body === undefined ? {} : { 'content-type': 'application/json' })
			},
			body: body === undefined ? undefined : JSON.stringify(body)
		})
	);
}

interface Figures {
	mode: string;
	modeIsDefault: boolean;
	counts: {
		listedAttempts: number;
		listedRightPassword: number;
		refused: number;
	};
}

async function figures(): Promise<Figures> {
	return (await (
		await call('GET', `/admin/api/projects/${bucketId}/password-guessing`)
	).json()) as Figures;
}

/**
 * @proves Once the list is on, every project counts password sign-ins from listed addresses without refusing anyone,
 * a project set to nothing counts nothing, the numbers never hold an address, and choosing Refuse is applied only
 * after the administrator has seen the last 7 days' numbers, which the audit trail records.
 */
describe("a project's numbers for listed addresses", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
		bucketId = await seedProject();
		cookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(await createAdministrator('super', 'count@x.io')))._id}`;
	});

	beforeEach(() => {
		resetAttackerList();
		undoClock = clockAt(0.1);
	});

	afterEach(async () => {
		undoClock();
		await setGuessing(bucketId, undefined);
	});

	it('counts and refuses nobody by default once the list is on', async () => {
		const from = listedAddress();
		const email = await person(bucketId);
		await listing(from);
		const before = await figures();

		const signedIn = await attempt(email, PASSWORD, from);
		const after = await figures();

		expect({
			status: signedIn.status,
			mode: after.mode,
			modeIsDefault: after.modeIsDefault,
			attempts: after.counts.listedAttempts - before.counts.listedAttempts,
			right:
				after.counts.listedRightPassword - before.counts.listedRightPassword
		}).toEqual({
			status: 303,
			mode: 'count',
			modeIsDefault: true,
			attempts: 1,
			right: 1
		});
	});

	it('counts a wrong password from a listed address without the right-password figure', async () => {
		const from = listedAddress();
		const email = await person(bucketId);
		await listing(from);
		const before = await figures();

		await attempt(email, WRONG, from);
		const after = await figures();

		expect([
			after.counts.listedAttempts - before.counts.listedAttempts,
			after.counts.listedRightPassword - before.counts.listedRightPassword
		]).toEqual([1, 0]);
	});

	it('counts nothing for a project set to nothing', async () => {
		const from = listedAddress();
		const email = await person(bucketId);
		await listing(from);
		await setGuessing(bucketId, { mode: 'nothing', exempt: [] });
		const before = await figures();

		await attempt(email, PASSWORD, from);

		expect((await figures()).counts).toEqual(before.counts);
	});

	it('stores the numbers without any address, account or email', async () => {
		const from = listedAddress();
		const email = await person(bucketId);
		await listing(from);
		await attempt(email, PASSWORD, from);
		await figures();

		const stored = JSON.stringify(
			await adapter('PasswordGuessingTally').findByIndexed('bucketId', bucketId)
		);
		const answered = JSON.stringify(await figures());

		expect({
			address: stored.includes(from) || answered.includes(from),
			email: stored.includes(email) || answered.includes(email)
		}).toEqual({ address: false, email: false });
	});

	it('answers choosing Refuse with the last 7 days of numbers and changes nothing', async () => {
		const from = listedAddress();
		await listing(from);
		await attempt(await person(bucketId), PASSWORD, from);
		const shown = await figures();

		const answer = await call('PATCH', `/admin/api/projects/${bucketId}`, {
			passwordGuessing: { mode: 'refuse', exempt: [] }
		});
		const body = (await answer.json()) as { expect?: Record<string, number> };

		expect({
			status: answer.status,
			expect: body.expect,
			mode: (await figures()).mode
		}).toEqual({
			status: 409,
			expect: {
				listedAttempts: shown.counts.listedAttempts,
				listedRightPassword: shown.counts.listedRightPassword
			},
			mode: 'count'
		});
	});

	it('applies Refuse when confirmed with the numbers shown', async () => {
		const shown = await figures();

		const answer = await call('PATCH', `/admin/api/projects/${bucketId}`, {
			passwordGuessing: { mode: 'refuse', exempt: [] },
			confirm: true,
			expect: {
				listedAttempts: shown.counts.listedAttempts,
				listedRightPassword: shown.counts.listedRightPassword
			}
		});

		expect({ status: answer.status, mode: (await figures()).mode }).toEqual({
			status: 200,
			mode: 'refuse'
		});
	});

	it('records the choice in the audit trail', async () => {
		await call('PATCH', `/admin/api/projects/${bucketId}`, {
			passwordGuessing: { mode: 'nothing', exempt: [] }
		});

		const entries = await adminAuditStore.list({ targetId: bucketId });
		const latest = entries.entries.find(
			(entry) => entry.action === 'bucket.update'
		);

		expect(latest?.attributes).toEqual(['passwordGuessing']);
	});
});
