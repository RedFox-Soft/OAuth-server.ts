import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore, getUserStore } from 'lib/adapters/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor } from '../admin/ownership_fixtures.ts';
import { shaped } from '../shape.ts';
import {
	ACME,
	mailOn,
	person,
	project,
	seedPasskey,
	type Project
} from './helpers.ts';

const Answer = Type.Object({
	passkeys: Type.Array(
		Type.Object({
			id: Type.String(),
			name: Type.Optional(Type.String()),
			createdOn: Type.Object({ browser: Type.String(), system: Type.String() }),
			synced: Type.Boolean(),
			createdAt: Type.String(),
			createdVia: Type.String(),
			lastUsedAt: Type.Optional(Type.String()),
			state: Type.String()
		})
	),
	ways: Type.Object({
		password: Type.Boolean(),
		providers: Type.Array(Type.String())
	}),
	restore: Type.String(),
	mailable: Type.Boolean()
});

async function list(
	at: Project,
	accountId: string,
	cookie: string
): Promise<{ status: number; body: unknown }> {
	const response = await elysia.handle(
		new Request(
			`http://e.ly/admin/api/projects/${at.bucketId}/users/${accountId}/passkeys`,
			{ headers: { cookie } }
		)
	);
	return { status: response.status, body: await response.json() };
}

/* Every key anywhere in a JSON value, at any depth. */
function keysIn(value: unknown): string[] {
	if (Array.isArray(value)) return value.flatMap(keysIn);
	if (typeof value !== 'object' || value === null) return [];
	return Object.entries(value).flatMap(([key, inner]) => [
		key,
		...keysIn(inner)
	]);
}

/**
 * @proves An administrator who can manage a project's people reads each passkey of a person there with whether it
 * signs in and why not, the person's other ways in and how someone left with none gets back; nothing secret about a
 * passkey leaves the server; and an administrator of another team reads nothing.
 */
describe('a person’s passkeys in the console', () => {
	let acme: Project;
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
		cookie = await cookieFor(await createAdministrator('super'));
		acme = await project(ACME);
	});

	beforeEach(async () => {
		await mailOn();
		forgetBucketAddresses();
		await getBucketStore().update(acme.bucketId, {
			passkeyLogin: true,
			passwordLogin: true
		});
	});

	it('lists each passkey, oldest first, with why one does not sign in', async () => {
		const { accountId } = await person(acme.bucketId);
		const works = await seedPasskey(acme.bucketId, accountId, {
			createdAt: new Date(Date.now() - 3000),
			name: 'Work laptop',
			lastUsedAt: new Date()
		});
		const moved = await seedPasskey(acme.bucketId, accountId, {
			createdAt: new Date(Date.now() - 2000),
			rpId: 'old.example.test'
		});
		const copied = await seedPasskey(acme.bucketId, accountId, {
			createdAt: new Date(Date.now() - 1000),
			copiedAt: new Date()
		});

		const answer = await list(acme, accountId, cookie);

		expect(answer.status).toBe(200);
		const read = shaped(Answer, answer.body);
		expect(read.passkeys.map((p) => [p.id, p.state])).toEqual([
			[works._id, 'works'],
			[moved._id, 'old_address'],
			[copied._id, 'copied']
		]);
		expect(read.passkeys[0]).toMatchObject({
			name: 'Work laptop',
			createdOn: { browser: 'chrome', system: 'windows' },
			synced: true,
			createdVia: 'password_code'
		});
		expect(read.passkeys[1]?.lastUsedAt).toBeUndefined();
		expect(read).toMatchObject({
			ways: { password: true, providers: [] },
			restore: 'self',
			mailable: true
		});
	});

	it('says a passkey made here does not sign in while the project turns passkeys off', async () => {
		const { accountId } = await person(acme.bucketId);
		await seedPasskey(acme.bucketId, accountId);
		await getBucketStore().update(acme.bucketId, { passkeyLogin: false });

		const read = shaped(Answer, (await list(acme, accountId, cookie)).body);

		expect(read.passkeys.map((p) => p.state)).toEqual(['off']);
	});

	it('never carries a passkey’s credential, key, counter, site or “This wasn’t me” state', async () => {
		const { accountId } = await person(acme.bucketId);
		await seedPasskey(acme.bucketId, accountId, {
			notMe: { digest: 'a'.repeat(64), exp: Math.floor(Date.now() / 1000) + 60 }
		});

		const answer = await list(acme, accountId, cookie);

		expect(answer.status).toBe(200);
		const forbidden = [
			'credentialId',
			'publicKey',
			'counter',
			'transports',
			'aaguid',
			'rpId',
			'notMe',
			'digest'
		];
		expect(
			keysIn(answer.body).filter((key) => forbidden.includes(key))
		).toEqual([]);
	});

	it('refuses an administrator of another team', async () => {
		const { accountId } = await person(acme.bucketId);
		await seedPasskey(acme.bucketId, accountId);
		const outsider = await cookieFor(await createAdministrator('plain'));

		const answer = await list(acme, accountId, outsider);

		expect([403, 404]).toContain(answer.status);
		expect(keysIn(answer.body)).not.toContain('passkeys');
	});

	describe('for someone a revocation could leave with no way in', () => {
		async function passkeyOnly(): Promise<string> {
			const { accountId } = await person(acme.bucketId);
			await getUserStore(acme.bucketId).update(accountId, {
				passwordSet: false
			});
			await seedPasskey(acme.bucketId, accountId);
			return accountId;
		}

		it('says they can choose a password themselves where the project lets them', async () => {
			const accountId = await passkeyOnly();

			const read = shaped(Answer, (await list(acme, accountId, cookie)).body);

			expect(read.ways).toEqual({ password: false, providers: [] });
			expect(read.restore).toBe('self');
		});

		it('says an administrator can set one when the person cannot reset it by mail', async () => {
			const accountId = await passkeyOnly();
			await mailOn(false);

			const read = shaped(Answer, (await list(acme, accountId, cookie)).body);

			expect(read.restore).toBe('admin');
		});

		it('says nobody can when the project takes no passwords', async () => {
			const accountId = await passkeyOnly();
			await getBucketStore().update(acme.bucketId, { passwordLogin: false });

			const read = shaped(Answer, (await list(acme, accountId, cookie)).body);

			expect(read.ways.password).toBe(false);
			expect(read.restore).toBe('none');
		});

		it('says nobody can for a provisioned person who cannot reset by mail', async () => {
			const accountId = await passkeyOnly();
			await getUserStore(acme.bucketId).update(accountId, {
				provisionedBy: 'a-connection'
			});
			await mailOn(false);

			const read = shaped(Answer, (await list(acme, accountId, cookie)).body);

			expect(read.restore).toBe('none');
		});
	});
});
