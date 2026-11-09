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
	REFUSAL_TITLE,
	seedProject,
	setGuessing
} from './door.ts';

let bucketId: string;
let undoClock: () => void = () => {};

/* A corroborated listing, so the address is refused at its first attempt unless exempt. */
async function listing(address: string): Promise<void> {
	const foxtrust = await signer();
	await publication().publish({
		version: `a${String(seconds(0))}`,
		builtAt: iso(0),
		validUntil: iso(3),
		lines: [{ network: address, lastSeen: seconds(-1), corroborated: true }],
		by: foxtrust
	});
	expect(await pass(foxtrust)).toBe('accepted');
}

/**
 * @proves A network a project exempts is never checked against the list while its exemption lasts, and the line a
 * refused person reads on their own page is enough for an administrator to let them back in.
 */
describe('networks a project never checks against the list', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
		bucketId = await seedProject();
	});

	beforeEach(() => {
		resetAttackerList();
		undoClock = clockAt(0.1);
	});

	afterEach(() => {
		undoClock();
	});

	it('lets an address in an exempt network sign in', async () => {
		const from = listedAddress();
		await listing(from);
		await setGuessing(bucketId, {
			mode: 'refuse',
			exempt: [{ network: `${from}/32` }]
		});

		const answer = await attempt(await person(bucketId), PASSWORD, from);

		expect(answer.status).toBe(303);
	});

	it('checks an address again once its exemption has ended', async () => {
		const from = listedAddress();
		await listing(from);
		await setGuessing(bucketId, {
			mode: 'refuse',
			exempt: [{ network: from, until: iso(-1) }]
		});

		const answer = await attempt(await person(bucketId), PASSWORD, from);

		expect(answer.text).toContain(REFUSAL_TITLE);
	});

	it('lets a refused person in once the address in their support line is exempted', async () => {
		const from = listedAddress();
		const email = await person(bucketId);
		await listing(from);
		await setGuessing(bucketId, { mode: 'refuse', exempt: [] });
		const refused = await attempt(email, PASSWORD, from);
		const reported = /listed-address · ([^ <]+) · /.exec(refused.text)?.[1];
		const admin = await createAdministrator(
			'super',
			`exempt-${Math.random()}@x.io`
		);
		await elysia.handle(
			new Request(`${ISSUER}/admin/api/projects/${bucketId}`, {
				method: 'PATCH',
				headers: {
					cookie: `${ADMIN_SESSION_COOKIE}=${(await sessionFor(admin))._id}`,
					'content-type': 'application/json'
				},
				body: JSON.stringify({
					passwordGuessing: {
						mode: 'refuse',
						exempt: [{ network: reported ?? 'none' }]
					}
				})
			})
		);

		const answer = await attempt(email, PASSWORD, from);

		expect(answer.status).toBe(303);
	});
});
