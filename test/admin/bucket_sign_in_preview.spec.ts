import {
	describe,
	it,
	expect,
	afterAll,
	beforeAll,
	beforeEach
} from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	getBucketStore,
	getProjectStore,
	getSmtpSettingsStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { SmtpSettings, User, UserBucket } from 'lib/adapters/types.ts';
import { ADMIN_BUCKET_ID, DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { shaped } from 'test/shape.ts';
import { provider } from '../scim/helpers.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor, regularGroup } from './ownership_fixtures.ts';
import { SignInPreview } from './sign_in_consent.ts';

async function request(
	method: string,
	path: string,
	cookie: string,
	body?: Readonly<Record<string, unknown>>
): Promise<{ status: number; body: unknown }> {
	const response = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: { 'content-type': 'application/json', cookie },
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		})
	);
	const text = await response.text();
	return {
		status: response.status,
		body: text ? (JSON.parse(text) as unknown) : null
	};
}

const StaleRefusal = Type.Intersect([
	SignInPreview,
	Type.Object({ error: Type.Literal('admin_error'), message: Type.String() })
]);
const Applied = Type.Object({
	passwordLogin: Type.Boolean(),
	registrationOpen: Type.Boolean(),
	emailVerificationRequired: Type.Boolean(),
	totpRequired: Type.Boolean(),
	name: Type.String()
});
const Summary = Type.Object({ projects: Type.Number() });

const MAIL: SmtpSettings = {
	host: 'smtp.example.test',
	port: 587,
	secure: false,
	username: '',
	password: '',
	fromName: 'Accounts',
	fromEmail: 'accounts@example.test'
};
const NO_MAIL: SmtpSettings = { ...MAIL, host: '', fromEmail: '' };

const ENROLMENT = {
	secret: 'JBSWY3DPEHPK3PXP',
	enrolledAt: new Date(),
	lastStep: 0
};

const slug = () =>
	`pv-${nanoid()
		.toLowerCase()
		.replace(/[^a-z0-9]/g, '')}`;

/**
 * @proves A bucket change that tightens who can get in is described before it is made — what it does to
 * whom, counted — and applied only when confirmed with the counts that were shown; a confirmation whose
 * counts no longer hold is refused with the fresh ones, nothing is recorded until it applies, and every
 * other change applies at once.
 */
describe('changing how people sign in to a bucket', () => {
	let owner: User;
	let cookie: string;
	let superCookie: string;
	let ownerGroupId: string;
	let previousMail: SmtpSettings | null = null;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
		owner = await createAdministrator();
		ownerGroupId = (await regularGroup([owner]))._id;
		cookie = await cookieFor(owner);
		superCookie = await cookieFor(await createAdministrator('super'));
		previousMail = await getSmtpSettingsStore().get();
		await getSmtpSettingsStore().set(MAIL);
	});

	afterAll(async () => {
		await getSmtpSettingsStore().set(previousMail ?? NO_MAIL);
	});

	/*
	 * Three people: one who can get in through the enabled provider, one linked only to a disabled one, and
	 * one with no link at all — unverified, and holding no authenticator.
	 */
	async function populatedBucket(
		fields: Partial<UserBucket> = {}
	): Promise<UserBucket> {
		const bucket = await getBucketStore().create({
			name: `preview ${nanoid()}`,
			slug: slug(),
			ownerGroupId,
			federation: [provider('corp'), provider('old', { enabled: false })],
			...fields
		});
		const users = getUserStore(bucket._id);
		const linked = await users.create(`linked-${nanoid()}@x.io`, 'h', true);
		await users.update(linked._id, {
			totp: ENROLMENT,
			federated: [{ providerId: 'corp', sub: nanoid(), linkedAt: new Date() }]
		});
		const stale = await users.create(`stale-${nanoid()}@x.io`, 'h', true);
		await users.update(stale._id, {
			federated: [{ providerId: 'old', sub: nanoid(), linkedAt: new Date() }]
		});
		await users.create(`plain-${nanoid()}@x.io`, 'h', false);
		return bucket;
	}

	const patch = (
		bucket: Pick<UserBucket, '_id'>,
		body: Readonly<Record<string, unknown>>,
		as = cookie
	) => request('PATCH', `/admin/api/buckets/${bucket._id}`, as, body);

	async function updatesRecorded(bucketId: string): Promise<number> {
		const { entries } = await adminAuditStore.list({
			targetId: bucketId,
			action: 'bucket.update'
		});
		return entries.length;
	}

	describe('turning password sign-in off', () => {
		it('answers how many people have no account at an enabled provider, out of everyone', async () => {
			const bucket = await populatedBucket();

			const answer = await patch(bucket, { passwordLogin: false });

			expect(answer.status).toBe(409);
			expect(shaped(SignInPreview, answer.body)).toEqual({
				confirmationRequired: true,
				consequences: [
					'2 of 3 users have no account at an enabled identity provider and could no longer sign in.'
				],
				expect: { withoutEnabledLink: 2 },
				changes: ['passwordsOff']
			});
		});

		it('changes nothing and records nothing until it is confirmed', async () => {
			const bucket = await populatedBucket();

			await patch(bucket, { passwordLogin: false });

			expect((await getBucketStore().find(bucket._id))?.passwordLogin).toBe(
				true
			);
			expect(await updatesRecorded(bucket._id)).toBe(0);
		});

		it('applies when confirmed with the counts shown, recording only the setting changed', async () => {
			const bucket = await populatedBucket();

			const answer = await patch(bucket, {
				passwordLogin: false,
				confirm: true,
				expect: { withoutEnabledLink: 2 }
			});

			expect(answer.status).toBe(200);
			expect(shaped(Applied, answer.body).passwordLogin).toBe(false);
			const { entries } = await adminAuditStore.list({
				targetId: bucket._id,
				action: 'bucket.update'
			});
			expect(entries.map((entry) => entry.attributes)).toEqual([
				['passwordLogin']
			]);
		});

		it('is refused with the fresh counts when somebody arrived since the preview', async () => {
			const bucket = await populatedBucket();
			const shown = shaped(
				SignInPreview,
				(await patch(bucket, { passwordLogin: false })).body
			);
			await getUserStore(bucket._id).create(`late-${nanoid()}@x.io`, 'h');

			const answer = await patch(bucket, {
				passwordLogin: false,
				confirm: true,
				expect: shown.expect
			});

			expect(answer.status).toBe(409);
			const refusal = shaped(StaleRefusal, answer.body);
			expect(refusal.message).toBe(
				'what this change affects changed since you reviewed it'
			);
			expect(refusal.expect).toEqual({ withoutEnabledLink: 3 });
			expect((await getBucketStore().find(bucket._id))?.passwordLogin).toBe(
				true
			);
			expect(await updatesRecorded(bucket._id)).toBe(0);
		});

		it('is refused when confirmed without the counts', async () => {
			const bucket = await populatedBucket();

			const answer = await patch(bucket, {
				passwordLogin: false,
				confirm: true
			});

			expect(answer.status).toBe(409);
			expect(shaped(StaleRefusal, answer.body).message).toBe(
				'confirm with the counts of the preview you reviewed (expect)'
			);
		});
	});

	it('requiring verification counts the people who have not verified their address', async () => {
		const bucket = await populatedBucket();

		const answer = await patch(bucket, { emailVerificationRequired: true });

		const preview = shaped(SignInPreview, answer.body);
		expect(preview.expect).toEqual({ unverified: 1 });
		expect(preview.consequences).toEqual([
			"1 user hasn't verified their address; each is sent a message at their next sign-in and cannot continue until they follow it."
		]);
	});

	it('requiring an authenticator counts the password users without one, an unknown password state among them', async () => {
		const bucket = await populatedBucket();
		const users = getUserStore(bucket._id);
		/* Created by an administrator without a password: never asked to enrol at a password sign-in. */
		const passwordless = await users.create(`nopw-${nanoid()}@x.io`, 'h');
		await users.update(passwordless._id, { passwordSet: false });

		const answer = await patch(bucket, { totpRequired: true });

		const preview = shaped(SignInPreview, answer.body);
		expect(preview.expect).toEqual({ passwordWithoutAuthenticator: 2 });
		expect(preview.changes).toEqual(['authenticatorOn']);
	});

	it('shows in the summary the counts a preview asks to be confirmed: links to enabled providers only, an unknown password state as a password', async () => {
		const bucket = await populatedBucket();
		const users = getUserStore(bucket._id);
		const passwordless = await users.create(`nopw-${nanoid()}@x.io`, 'h');
		await users.update(passwordless._id, { passwordSet: false });

		const answer = await request(
			'GET',
			`/admin/api/buckets/${bucket._id}/summary`,
			cookie
		);

		const summary = shaped(
			Type.Object({
				users: Type.Number(),
				withoutEnabledLink: Type.Number(),
				passwordWithoutAuthenticator: Type.Number(),
				projects: Type.Optional(Type.Number())
			}),
			answer.body
		);
		expect(summary).toEqual({
			...summary,
			users: 4,
			withoutEnabledLink: 3,
			passwordWithoutAuthenticator: 2
		});
		/* Counted on the default bucket only, where a project naming no bucket signs in. */
		expect(summary.projects).toBeUndefined();
	});

	it('requiring an authenticator while password sign-in stays off applies at once, with the advisory', async () => {
		const bucket = await populatedBucket({ passwordLogin: false });

		const answer = await patch(bucket, { totpRequired: true });

		expect(answer.status).toBe(200);
		expect(JSON.stringify(answer.body)).toContain('has no effect');
	});

	it('names every change of one request in one preview', async () => {
		const bucket = await populatedBucket();

		const answer = await patch(bucket, {
			passwordLogin: false,
			emailVerificationRequired: true
		});

		const preview = shaped(SignInPreview, answer.body);
		expect(preview.changes).toEqual(['passwordsOff', 'verificationOn']);
		expect(preview.expect).toEqual({ withoutEnabledLink: 2, unverified: 1 });
	});

	it.each([
		['a rename', { name: 'renamed' }],
		['closing sign-up', { registrationOpen: false }],
		['opening sign-up on an ordinary bucket', { registrationOpen: true }],
		['turning a requirement off', { emailVerificationRequired: false }],
		['a different verification method', { verificationMethod: 'code' }]
	])('applies %s at once, without a preview', async (_, body) => {
		const bucket = await populatedBucket({ emailVerificationRequired: true });

		const answer = await patch(bucket, body);

		expect(answer.status).toBe(200);
		expect(await updatesRecorded(bucket._id)).toBe(1);
	});

	describe('on the default bucket', () => {
		let before: UserBucket | null = null;

		beforeEach(async () => {
			before ??= await getBucketStore().find(DEFAULT_BUCKET_ID);
			await getBucketStore().update(DEFAULT_BUCKET_ID, {
				registrationOpen: false
			});
		});

		afterAll(async () => {
			if (before) {
				await getBucketStore().update(DEFAULT_BUCKET_ID, {
					registrationOpen: before.registrationOpen
				});
			}
		});

		async function projectsCounted(): Promise<number> {
			const answer = await request(
				'GET',
				`/admin/api/buckets/${DEFAULT_BUCKET_ID}/summary`,
				superCookie
			);
			return shaped(Summary, answer.body).projects;
		}

		it('counts a project naming the default bucket and one naming no bucket as signing in there', async () => {
			const counted = await projectsCounted();
			await getProjectStore().create({
				name: `names it ${nanoid()}`,
				slug: slug(),
				ownerGroupId,
				bucketId: DEFAULT_BUCKET_ID
			});
			await getProjectStore().create({
				name: `names none ${nanoid()}`,
				slug: slug(),
				ownerGroupId,
				bucketId: null
			});

			expect(await projectsCounted()).toBe(counted + 2);
		});

		it('opening sign-up says anyone can create an account, and how many projects it changes sign-in for', async () => {
			const projects = await projectsCounted();

			const answer = await request(
				'PATCH',
				`/admin/api/buckets/${DEFAULT_BUCKET_ID}`,
				superCookie,
				{ registrationOpen: true }
			);

			expect(answer.status).toBe(409);
			expect(shaped(SignInPreview, answer.body)).toMatchObject({
				consequences: [
					'Anyone who can reach the sign-in page can create an account.',
					`This changes sign-in for ${projects} project${projects === 1 ? '' : 's'}.`
				],
				expect: { projects },
				changes: ['signUpOpen']
			});
		});
	});

	it("opening sign-up on the administrators' bucket says anyone can create an administrator account", async () => {
		try {
			const answer = await request(
				'PATCH',
				`/admin/api/buckets/${ADMIN_BUCKET_ID}`,
				superCookie,
				{ registrationOpen: true }
			);

			expect(shaped(SignInPreview, answer.body).consequences).toEqual([
				'Anyone who can reach the sign-in page can create an administrator account.'
			]);
		} finally {
			await getBucketStore().update(ADMIN_BUCKET_ID, {
				registrationOpen: false
			});
		}
	});

	it("gives a super administrator the administrators' bucket counts", async () => {
		const answer = await request(
			'GET',
			`/admin/api/buckets/${ADMIN_BUCKET_ID}/summary`,
			superCookie
		);

		expect(answer.status).toBe(200);
		expect(
			shaped(
				Type.Object({
					withoutEnabledLink: Type.Number(),
					passwordWithoutAuthenticator: Type.Number()
				}),
				answer.body
			).withoutEnabledLink
		).toBeGreaterThan(0);
	});
});
