import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getBucketStore,
	getPasskeyStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { present, shaped } from '../shape.ts';
import {
	call,
	createProject,
	freshSlug,
	saveAddressForms,
	superAdministrator,
	type Caller
} from '../subdomain_projects/admin.ts';
import { person, seedPasskey } from './helpers.ts';

const Lost = Type.Object({
	passkeys: Type.Number(),
	people: Type.Number(),
	withOtherWay: Type.Number(),
	withoutOtherWay: Type.Number(),
	without: Type.Array(Type.String()),
	more: Type.Number()
});
const Preview = Type.Object({
	passkeys: Type.Optional(Lost),
	consequence: Type.String(),
	expect: Type.Record(Type.String(), Type.Number())
});
const Listed = Type.Object({
	passkeys: Type.Array(Type.Object({ state: Type.String() }))
});
const Summary = Type.Object({ passkeyHolders: Type.Optional(Type.Number()) });

let operator: Caller;

/* A project at a path of the instance, accepting passkeys: its passkeys are made for the instance's host. */
async function pathProject(): Promise<{ id: string; slug: string }> {
	const slug = freshSlug('keys');
	const created = await createProject(operator, { slug });
	const id = shaped(Type.Object({ _id: Type.String() }), created.body)._id;
	await getBucketStore().update(id, { passkeyLogin: true });
	forgetBucketAddresses();
	return { id, slug };
}

/* Someone holding a passkey of the project's site, with a password or without. */
async function holder(
	bucketId: string,
	{ password, fields = {} }: { password: boolean; fields?: object }
): Promise<{ email: string; accountId: string }> {
	const who = await person(bucketId);
	if (!password) {
		await getUserStore(bucketId).update(who.accountId, { passwordSet: false });
	}
	await seedPasskey(bucketId, who.accountId, fields);
	return who;
}

async function preview(
	id: string,
	body: Record<string, unknown>
): Promise<{ status: number; body: unknown }> {
	const answer = await call(
		'POST',
		`/admin/api/projects/${id}/address`,
		operator.cookie,
		body
	);
	forgetBucketAddresses();
	return answer;
}

/**
 * @proves Before a project moves to an address that changes where its passkeys work, its operator is told how many
 * passkeys of how many people stop working, how many of those people keep another way in, and who has none; a move
 * that keeps their site says nothing; a confirmation given before those numbers changed is refused; the move deletes no
 * passkey; and the Sign-in tab counts the people holding a passkey that signs in at the project's address.
 */
describe('passkeys and a project’s address', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
		operator = await superAdministrator();
	});

	beforeEach(async () => {
		forgetBucketAddresses();
		await saveAddressForms(operator.cookie, 'both');
	});

	it('counts what a move to a subdomain stops, and names who is left with no way in', async () => {
		const { id, slug } = await pathProject();
		await holder(id, { password: true });
		await holder(id, { password: true });
		const vera = await holder(id, { password: false });
		await holder(id, { password: false, fields: { copiedAt: new Date() } });
		await holder(id, { password: false, fields: { rpId: 'old.example.test' } });

		const asked = await preview(id, { slug, addressForm: 'subdomain' });

		expect(asked.status).toBe(409);
		const read = shaped(Preview, asked.body);
		expect(read.passkeys).toEqual({
			passkeys: 3,
			people: 3,
			withOtherWay: 2,
			withoutOtherWay: 1,
			without: [vera.email],
			more: 0
		});
		expect(read.expect).toMatchObject({ passkeyPeople: 3, passkeyOnly: 1 });
		expect(read.consequence).toContain('every passkey listed stops working');
	});

	it('says nothing about passkeys when the move keeps their site', async () => {
		const { id } = await pathProject();
		await holder(id, { password: false });

		const asked = await preview(id, {
			slug: freshSlug('renamed'),
			addressForm: 'path'
		});

		const read = shaped(Preview, asked.body);
		expect(read.passkeys).toBeUndefined();
		expect(Object.keys(read.expect)).not.toContain('passkeyPeople');
		expect(read.consequence).not.toContain('passkey');
	});

	it('counts them while the project has passkeys turned off, since the move ends them for good', async () => {
		const { id, slug } = await pathProject();
		await holder(id, { password: true });
		await getBucketStore().update(id, { passkeyLogin: false });

		const read = shaped(
			Preview,
			(await preview(id, { slug, addressForm: 'subdomain' })).body
		);

		expect(read.passkeys?.people).toBe(1);
	});

	it('names the first twenty people left with no way in, and counts the rest', async () => {
		const { id, slug } = await pathProject();
		for (let n = 0; n < 21; n++) await holder(id, { password: false });

		const read = shaped(
			Preview,
			(await preview(id, { slug, addressForm: 'subdomain' })).body
		);

		expect(read.passkeys?.without.length).toBe(20);
		expect(read.passkeys?.more).toBe(1);
	});

	it('counts a passkey already made for the new address as a way in', async () => {
		const { id, slug } = await pathProject();
		const back = await holder(id, { password: false });
		await seedPasskey(id, back.accountId, { rpId: `${slug}.e.ly` });

		const read = shaped(
			Preview,
			(await preview(id, { slug, addressForm: 'subdomain' })).body
		);

		expect(read.passkeys).toMatchObject({
			withOtherWay: 1,
			withoutOtherWay: 0
		});
	});

	it('refuses a confirmation given before someone lost their other way in, and moves nothing', async () => {
		const { id, slug } = await pathProject();
		const anna = await holder(id, { password: true });
		const body = { slug, addressForm: 'subdomain' };
		const seen = shaped(Preview, (await preview(id, body)).body).expect;
		await getUserStore(id).update(anna.accountId, { passwordSet: false });

		const confirmed = await preview(id, {
			...body,
			confirm: true,
			expect: seen
		});

		expect(confirmed.status).toBe(409);
		expect(shaped(Preview, confirmed.body).expect.passkeyOnly).toBe(1);
		const after = present(await getBucketStore().find(id), 'the project');
		expect(after.subdomain).toBeUndefined();
	});

	it('moves once confirmed with the numbers it showed, and deletes no passkey', async () => {
		const { id, slug } = await pathProject();
		const anna = await holder(id, { password: true });
		const body = { slug, addressForm: 'subdomain' };
		const seen = shaped(Preview, (await preview(id, body)).body).expect;

		const moved = await preview(id, { ...body, confirm: true, expect: seen });

		expect(moved.status).toBe(200);
		const listed = await call(
			'GET',
			`/admin/api/projects/${id}/users/${anna.accountId}/passkeys`,
			operator.cookie
		);
		expect(
			shaped(Listed, listed.body).passkeys.map((passkey) => passkey.state)
		).toEqual(['old_address']);
	});

	/*
	 * SC-007 asks for 50,000 holders; measured once at that size (specs/140 tasks.md Results: 145 ms), it is kept here at
	 * 5,000, because seeding the in-memory stores grows faster than the preview does and would cost the suite minutes.
	 */
	it('answers the preview within two seconds when thousands of people hold passkeys', async () => {
		const { id, slug } = await pathProject();
		const users = getUserStore(id);
		const store = getPasskeyStore();
		const template = await seedPasskey(id, (await person(id)).accountId);
		for (let n = 0; n < 5_000; n++) {
			const user = await users.create(`bulk-${String(n)}@acme.test`, 'x', true);
			await store.create({
				...template,
				_id: `p${String(n).padStart(21, '0')}`,
				accountId: user._id,
				credentialId: `c${String(n)}`
			});
		}

		const started = performance.now();
		const asked = await preview(id, { slug, addressForm: 'subdomain' });
		const took = performance.now() - started;

		expect(shaped(Preview, asked.body).passkeys?.people).toBe(5_001);
		expect(took).toBeLessThan(2000);
	}, 120_000);

	describe('on the Sign-in tab', () => {
		it('counts the people holding a passkey that signs in at the project’s address', async () => {
			const { id } = await pathProject();
			const twice = await holder(id, { password: true });
			await seedPasskey(id, twice.accountId);
			await holder(id, { password: false });
			await holder(id, { password: false, fields: { copiedAt: new Date() } });
			await holder(id, {
				password: false,
				fields: { rpId: 'old.example.test' }
			});

			const summary = await call(
				'GET',
				`/admin/api/projects/${id}/summary`,
				operator.cookie
			);

			expect(shaped(Summary, summary.body).passkeyHolders).toBe(2);
		});

		it('counts nothing for the administrators’ project', async () => {
			const summary = await call(
				'GET',
				`/admin/api/projects/${ADMIN_BUCKET_ID}/summary`,
				operator.cookie
			);

			expect(summary.status).toBe(200);
			expect(shaped(Summary, summary.body).passkeyHolders).toBeUndefined();
		});
	});
});
