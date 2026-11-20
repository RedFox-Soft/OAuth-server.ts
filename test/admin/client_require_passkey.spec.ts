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
import { relyingPartyOf } from 'lib/passkeys/relying_party.ts';
import { shaped } from 'test/shape.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor, regularGroup } from './ownership_fixtures.ts';
import { seedPasskey } from '../passkeys/helpers.ts';

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
	expect: Type.Record(Type.String(), Type.Number()),
	changes: Type.Array(Type.String())
});
const View = Type.Object({
	clientId: Type.String(),
	requireCode: Type.Boolean(),
	requirePasskey: Type.Boolean()
});
const Refusal = Type.Object({ code: Type.String(), message: Type.String() });

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
	clientName: 'Payments',
	grantTypes: ['authorization_code'],
	tokenEndpointAuthMethod: 'client_secret_basic',
	redirectUris: ['https://payments.example.com/cb']
};

/**
 * @proves Making an application require a passkey is described before it is made — how many of the project's people
 * have no confirmed passkey, how many can sign in only through a provider, how many hold a sign-in to it — and applied
 * only when confirmed with those counts and recorded; it is refused in a project that does not accept passkeys, and
 * turning the project's passkeys off names the applications that require one.
 */
describe('making an application require a passkey', () => {
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

	/*
	 * Four people: one holding a full passkey, one holding only a conditional one, one with a password and none, one who
	 * has no password at all.
	 */
	async function project(
		fields: Partial<UserBucket> = { passkeyLogin: true }
	): Promise<{ bucket: UserBucket; clientId: string }> {
		const fresh = await getBucketStore().create({
			name: `passkey ${nanoid()}`,
			slug: `rp-${nanoid()
				.toLowerCase()
				.replace(/[^a-z0-9]/g, '')}`,
			ownerGroupId
		});
		const bucket = (await getBucketStore().update(fresh._id, fields)) ?? fresh;
		const users = getUserStore(bucket._id);
		const { rpId } = relyingPartyOf(bucket);
		const seed = (accountId: string, conditional: boolean) =>
			seedPasskey(bucket._id, accountId, {
				rpId,
				...(conditional
					? { conditional: true, createdVia: 'password' as const }
					: {})
			});
		await seed(
			(await users.create(`full-${nanoid()}@x.io`, 'h', true))._id,
			false
		);
		await seed(
			(await users.create(`cond-${nanoid()}@x.io`, 'h', true))._id,
			true
		);
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

	it('answers who would be turned away, and changes and records nothing', async () => {
		const { bucket, clientId } = await project();

		const answer = await patch(bucket, clientId, { requirePasskey: true });

		expect(answer.status).toBe(409);
		const preview = shaped(Preview, answer.body);
		expect(preview.changes).toEqual(['requirePasskeyOn']);
		expect(preview.expect).toEqual({
			withoutPasskey: 3,
			providerOnly: 1,
			holders: 0
		});
		expect(preview.consequences.join(' ')).toContain('no confirmed passkey');
		expect(await updatesRecorded(clientId)).toHaveLength(0);
	});

	it('applies when confirmed with the counts shown, and records it', async () => {
		const { bucket, clientId } = await project();

		const answer = await patch(bucket, clientId, {
			requirePasskey: true,
			confirm: true,
			expect: { withoutPasskey: 3, providerOnly: 1, holders: 0 }
		});

		expect(answer.status).toBe(200);
		expect(shaped(View, answer.body).requirePasskey).toBe(true);
		expect(await updatesRecorded(clientId)).toHaveLength(1);
	});

	it('asks again when the counts it was confirmed with are not the current ones', async () => {
		const { bucket, clientId } = await project();

		const answer = await patch(bucket, clientId, {
			requirePasskey: true,
			confirm: true,
			expect: { withoutPasskey: 0, providerOnly: 1, holders: 0 }
		});

		expect(answer.status).toBe(409);
		expect(await updatesRecorded(clientId)).toHaveLength(0);
	});

	it('takes one confirmation of both counts when both requirements turn on together', async () => {
		const { bucket, clientId } = await project();

		const asked = shaped(
			Preview,
			(
				await patch(bucket, clientId, {
					requirePasskey: true,
					requireCode: true
				})
			).body
		);
		const answer = await patch(bucket, clientId, {
			requirePasskey: true,
			requireCode: true,
			confirm: true,
			expect: asked.expect
		});

		expect(asked.changes).toEqual(['requirePasskeyOn', 'requireCodeOn']);
		expect(answer.status).toBe(200);
	});

	it('is refused, with nothing recorded, in a project that does not accept passkeys', async () => {
		const { bucket, clientId } = await project({ passkeyLogin: false });

		const answer = await patch(bucket, clientId, { requirePasskey: true });

		expect(answer.status).toBe(409);
		expect(shaped(Refusal, answer.body).code).toBe('passkeys_not_accepted');
		expect(await updatesRecorded(clientId)).toHaveLength(0);
	});

	it('is lifted at once, with no preview', async () => {
		const { bucket, clientId } = await project();
		await patch(bucket, clientId, {
			requirePasskey: true,
			confirm: true,
			expect: { withoutPasskey: 3, providerOnly: 1, holders: 0 }
		});

		const answer = await patch(bucket, clientId, { requirePasskey: false });

		expect(answer.status).toBe(200);
		expect(shaped(View, answer.body).requirePasskey).toBe(false);
	});

	it('names the application when the project’s passkeys are about to be turned off', async () => {
		const { bucket, clientId } = await project();
		await patch(bucket, clientId, {
			requirePasskey: true,
			confirm: true,
			expect: { withoutPasskey: 3, providerOnly: 1, holders: 0 }
		});

		const answer = await request(
			'PATCH',
			`/admin/api/projects/${bucket._id}`,
			cookie,
			{ passkeyLogin: false }
		);

		expect(answer.status).toBe(409);
		const preview = shaped(Preview, answer.body);
		expect(preview.expect.appsRequiringPasskey).toBe(1);
		expect(preview.consequences.join(' ')).toContain(
			'1 application requires a passkey: Payments.'
		);
	});
});
