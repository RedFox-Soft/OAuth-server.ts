import { afterAll, beforeAll, describe, expect, it } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	getBucketStore,
	getSmtpSettingsStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { SmtpSettings, User, UserBucket } from 'lib/adapters/types.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { shaped } from 'test/shape.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor, regularGroup } from './ownership_fixtures.ts';

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

const Preview = Type.Object({
	confirmationRequired: Type.Literal(true),
	consequences: Type.Array(Type.String()),
	expect: Type.Object({
		withoutAuthenticator: Type.Number(),
		providerOnly: Type.Number(),
		holders: Type.Number()
	}),
	changes: Type.Array(Type.String())
});
const View = Type.Object({
	clientId: Type.String(),
	requireCode: Type.Boolean()
});

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

const CLIENT_BODY = {
	clientName: 'Billing',
	grantTypes: ['authorization_code'],
	tokenEndpointAuthMethod: 'client_secret_basic',
	redirectUris: ['https://billing.example.com/cb']
};

/**
 * @proves Making an application require a code is described before it is made — how many of the project's people
 * have no authenticator app, how many can sign in only through a provider, how many hold a sign-in to it now — and
 * applied only when confirmed with those counts; nothing is recorded until it applies, lifting it applies at once, and
 * the administrators' applications cannot be given it at all.
 */
describe('making an application require a code', () => {
	let owner: User;
	let cookie: string;
	let ownerGroupId: string;
	let previousMail: SmtpSettings | null = null;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
		owner = await createAdministrator();
		ownerGroupId = (await regularGroup([owner]))._id;
		cookie = await cookieFor(owner);
		previousMail = await getSmtpSettingsStore().get();
		await getSmtpSettingsStore().set(MAIL);
	});

	afterAll(async () => {
		await getSmtpSettingsStore().set(previousMail ?? NO_MAIL);
	});

	/* Three people: one with an authenticator app, one with a password and none, one who has no password at all. */
	async function project(
		fields: Partial<UserBucket> = {}
	): Promise<{ bucket: UserBucket; clientId: string }> {
		const fresh = await getBucketStore().create({
			name: `code ${nanoid()}`,
			slug: `rc-${nanoid()
				.toLowerCase()
				.replace(/[^a-z0-9]/g, '')}`,
			ownerGroupId
		});
		const bucket = (await getBucketStore().update(fresh._id, fields)) ?? fresh;
		const users = getUserStore(bucket._id);
		const enrolled = await users.create(`enrolled-${nanoid()}@x.io`, 'h', true);
		await users.update(enrolled._id, {
			totp: {
				secret: 'JBSWY3DPEHPK3PXP',
				enrolledAt: new Date(),
				lastStep: 0,
				via: 'self'
			}
		});
		await users.create(`plain-${nanoid()}@x.io`, 'h', true);
		const federated = await users.create(`fed-${nanoid()}@x.io`, 'h', true);
		await users.update(federated._id, { passwordSet: false });
		const created = await request(
			'POST',
			`/admin/api/projects/${bucket._id}/clients`,
			cookie,
			CLIENT_BODY
		);
		expect(created.status).toBe(201);
		return { bucket, clientId: shaped(View, created.body).clientId };
	}

	const patch = (
		bucket: UserBucket,
		clientId: string,
		body: Readonly<Record<string, unknown>>
	) =>
		request(
			'PATCH',
			`/admin/api/projects/${bucket._id}/clients/${clientId}`,
			cookie,
			body
		);

	async function updatesRecorded(clientId: string) {
		const { entries } = await adminAuditStore.list({
			targetId: clientId,
			action: 'client.update'
		});
		return entries;
	}

	it('answers what it would do to whom, and changes and records nothing', async () => {
		const { bucket, clientId } = await project();

		const answer = await patch(bucket, clientId, { requireCode: true });

		expect(answer.status).toBe(409);
		const preview = shaped(Preview, answer.body);
		expect(preview.expect).toEqual({
			withoutAuthenticator: 1,
			providerOnly: 1,
			holders: 0
		});
		expect(preview.consequences.join(' ')).toContain(
			'They will be asked to set one up first.'
		);
		expect(preview.consequences.join(' ')).toContain(
			'unmet_authentication_requirements'
		);
		const view = await request(
			'GET',
			`/admin/api/projects/${bucket._id}/clients/${clientId}`,
			cookie
		);
		expect(shaped(View, view.body).requireCode).toBe(false);
		expect(await updatesRecorded(clientId)).toHaveLength(0);
	});

	it('says people will be turned away when they cannot set one up themselves', async () => {
		const { bucket, clientId } = await project({ totpSelfService: false });

		const answer = await patch(bucket, clientId, { requireCode: true });

		expect(shaped(Preview, answer.body).consequences.join(' ')).toContain(
			'does not let people set one up themselves'
		);
	});

	it('applies when confirmed with the counts shown, recording only the setting', async () => {
		const { bucket, clientId } = await project();

		const answer = await patch(bucket, clientId, {
			requireCode: true,
			confirm: true,
			expect: { withoutAuthenticator: 1, providerOnly: 1, holders: 0 }
		});

		expect(answer.status).toBe(200);
		expect(shaped(View, answer.body).requireCode).toBe(true);
		expect(
			(await updatesRecorded(clientId)).map((entry) => entry.attributes)
		).toEqual([['requireCode']]);
	});

	it('refuses a confirmation whose counts no longer hold, with the fresh ones', async () => {
		const { bucket, clientId } = await project();

		const answer = await patch(bucket, clientId, {
			requireCode: true,
			confirm: true,
			expect: { withoutAuthenticator: 7, providerOnly: 1, holders: 0 }
		});

		expect(answer.status).toBe(409);
		expect(shaped(Preview, answer.body).expect.withoutAuthenticator).toBe(1);
		expect(await updatesRecorded(clientId)).toHaveLength(0);
	});

	it('lifts it at once', async () => {
		const { bucket, clientId } = await project();
		await patch(bucket, clientId, {
			requireCode: true,
			confirm: true,
			expect: { withoutAuthenticator: 1, providerOnly: 1, holders: 0 }
		});

		const answer = await patch(bucket, clientId, { requireCode: false });

		expect(answer.status).toBe(200);
		expect(shaped(View, answer.body).requireCode).toBe(false);
	});

	it('previews it on a new application too', async () => {
		const { bucket } = await project();

		const answer = await request(
			'POST',
			`/admin/api/projects/${bucket._id}/clients`,
			cookie,
			{ ...CLIENT_BODY, requireCode: true }
		);

		expect(answer.status).toBe(409);
		expect(shaped(Preview, answer.body).expect.holders).toBe(0);
	});

	it('cannot be given to an administrators’ application', async () => {
		const superCookie = await cookieFor(await createAdministrator('super'));

		const answer = await request(
			'POST',
			'/admin/api/administrators/applications',
			superCookie,
			{
				clientName: 'Ops tool',
				redirectUris: ['https://ops.example/cb'],
				requireCode: true
			}
		);

		expect(answer.status).toBeGreaterThanOrEqual(400);
		expect(answer.status).toBeLessThan(500);
	});
});
