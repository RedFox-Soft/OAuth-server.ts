import { afterEach, beforeAll, describe, expect, it, spyOn } from 'bun:test';
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from 'jose';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.ts';
import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adminAuditStore, getBucketStore } from 'lib/adapters/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { KEY_PUBLICATION_SECONDS, keysFor } from 'lib/keys/issuer_keys.ts';
import { present, shaped } from '../shape.ts';
import { administrator, call, listed, ownedBucket } from './keys_admin.ts';
import { addresses, machineToken, publishedKeys, tenant } from './tenants.ts';

async function publishedKids(slug: string) {
	const response = await elysia.handle(new Request(`${ISSUER}/${slug}/jwks`));
	const { keys } = (await response.json()) as { keys: Array<{ kid: string }> };
	return keys.map((key) => key.kid);
}

/* Moves the clock forward by `seconds`, from the time it is called; again on a clock already moved. */
function later(seconds: number) {
	const at = Date.now() + seconds * 1000;
	const moved = Date.now as unknown as {
		mockReturnValue?: (value: number) => void;
	};
	if (moved.mockReturnValue) moved.mockReturnValue(at);
	else spyOn(Date, 'now').mockReturnValue(at);
}

const Rotation = Type.Object({
	alg: Type.String(),
	promoted: Type.Optional(Type.String()),
	demoted: Type.Optional(Type.String()),
	generated: Type.String(),
	rotatableAt: Type.Optional(Type.String())
});

const Revocation = Type.Object({
	kid: Type.String(),
	state: Type.Literal('revoked'),
	replacement: Type.Optional(Type.String()),
	replacementGenerated: Type.Boolean()
});

const KeyRead = Type.Object(
	{
		kid: Type.String(),
		state: Type.String(),
		promotableAt: Type.Optional(Type.String()),
		signedUntil: Type.Optional(Type.String())
	},
	{ additionalProperties: true }
);

async function generate(bucketId: string, cookie: string, alg: string) {
	const res = await call(
		'POST',
		`/admin/api/projects/${bucketId}/keys`,
		cookie,
		{
			alg
		}
	);
	return shaped(KeyRead, res.body);
}

async function rotate(bucketId: string, cookie: string, alg: string) {
	return call('POST', `/admin/api/projects/${bucketId}/keys/rotate`, cookie, {
		alg
	});
}

async function revoke(
	bucketId: string,
	cookie: string,
	kid: string,
	// null sends no body at all; a default parameter would stand in for an explicit undefined.
	confirm: string | null = kid
) {
	return call(
		'POST',
		`/admin/api/projects/${bucketId}/keys/${encodeURIComponent(kid)}/revoke`,
		cookie,
		confirm === null ? undefined : { confirm }
	);
}

async function states(bucketId: string, cookie: string) {
	return Object.fromEntries(
		(await listed(bucketId, cookie)).map((key) => [key.kid, key.state])
	);
}

async function entriesOf(userId: string, action: string) {
	return (await adminAuditStore.list({ actor: userId, action })).entries;
}

/**
 * @proves An administrator rotates an algorithm of a bucket's keys in one act that never promotes a key
 * inside its publication window, and revokes a possibly compromised key so that it leaves the key set and
 * every verification at once — a signer only together with the key that replaces it — each act refused
 * unless named and recorded once, naming every key it touched.
 */
describe('rotating and revoking a bucket key', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'bucket_keys' });
		await ensureAdminSeed();
	});

	afterEach(() => {
		(Date.now as unknown as { mockRestore?: () => void }).mockRestore?.();
	});

	describe('rotating', () => {
		it('only publishes the next key, and says from when the algorithm can rotate, while no key is ready', async () => {
			const { cookie, groupId } = await administrator('plain');
			const bucket = await ownedBucket(groupId);
			const [initial] = await listed(bucket._id, cookie);

			const res = await rotate(bucket._id, cookie, 'RS256');

			expect(res.status).toBe(200);
			const rotation = shaped(Rotation, res.body);
			expect(rotation.promoted).toBeUndefined();
			expect(rotation.demoted).toBeUndefined();
			const generated = (await listed(bucket._id, cookie)).find(
				(key) => key.kid === rotation.generated
			);
			expect(
				shaped(KeyRead, present(generated, 'the generated key')).promotableAt
			).toBe(present(rotation.rotatableAt, 'rotatableAt'));
			expect(await states(bucket._id, cookie)).toEqual({
				[initial.kid]: 'signing',
				[rotation.generated]: 'published'
			});
		});

		it('makes the older of two ready keys sign, returns the old signer to published, and publishes one new key', async () => {
			const { cookie, groupId } = await administrator('plain');
			const bucket = await ownedBucket(groupId);
			const [initial] = await listed(bucket._id, cookie);
			const older = await generate(bucket._id, cookie, 'RS256');
			later(1);
			const newer = await generate(bucket._id, cookie, 'RS256');
			later(KEY_PUBLICATION_SECONDS + 1);

			const res = await rotate(bucket._id, cookie, 'RS256');

			expect(res.status).toBe(200);
			const rotation = shaped(Rotation, res.body);
			expect([rotation.promoted, rotation.demoted]).toEqual([
				older.kid,
				initial.kid
			]);
			expect(rotation.rotatableAt).toBeUndefined();
			expect(await states(bucket._id, cookie)).toEqual({
				[initial.kid]: 'published',
				[older.kid]: 'signing',
				[newer.kid]: 'published',
				[rotation.generated]: 'published'
			});
		});

		it('states until when the replaced signer signed', async () => {
			const { cookie, groupId } = await administrator('plain');
			const bucket = await ownedBucket(groupId);
			const [initial] = await listed(bucket._id, cookie);
			await generate(bucket._id, cookie, 'RS256');
			later(KEY_PUBLICATION_SECONDS + 1);
			const rotatedAt = Date.now();

			await rotate(bucket._id, cookie, 'RS256');

			const { body } = await call(
				'GET',
				`/admin/api/projects/${bucket._id}/keys`,
				cookie
			);
			const keys = shaped(
				Type.Object({ keys: Type.Array(KeyRead) }),
				body
			).keys;
			expect(keys.find((key) => key.kid === initial.kid)?.signedUntil).toBe(
				new Date(rotatedAt).toISOString()
			);
		});

		it('records the rotation once, naming the promoted, demoted and generated keys', async () => {
			const { cookie, groupId, userId } = await administrator('plain');
			const bucket = await ownedBucket(groupId);
			const [initial] = await listed(bucket._id, cookie);
			const next = await generate(bucket._id, cookie, 'RS256');
			later(KEY_PUBLICATION_SECONDS + 1);

			const rotation = shaped(
				Rotation,
				(await rotate(bucket._id, cookie, 'RS256')).body
			);

			const entries = await entriesOf(userId, 'bucket.key.rotate');
			expect(
				entries.map((entry) => [entry.targetId, entry.kid, entry.keys])
			).toEqual([
				[
					bucket._id,
					next.kid,
					{
						promoted: next.kid,
						demoted: initial.kid,
						generated: rotation.generated
					}
				]
			]);
		});

		it('is refused for an algorithm no key can be generated in, and records nothing', async () => {
			const { cookie, groupId, userId } = await administrator('plain');
			const bucket = await ownedBucket(groupId);

			const res = await rotate(bucket._id, cookie, 'HS256');

			expect(res.status).toBe(422);
			expect(await entriesOf(userId, 'bucket.key.rotate')).toEqual([]);
		});

		it('never makes a revoked key sign', async () => {
			const { cookie, groupId } = await administrator('plain');
			const bucket = await ownedBucket(groupId);
			const [initial] = await listed(bucket._id, cookie);
			const compromised = await generate(bucket._id, cookie, 'RS256');
			later(KEY_PUBLICATION_SECONDS + 1);
			await revoke(bucket._id, cookie, compromised.kid);

			const rotation = shaped(
				Rotation,
				(await rotate(bucket._id, cookie, 'RS256')).body
			);

			expect(rotation.promoted).toBeUndefined();
			expect((await states(bucket._id, cookie))[initial.kid]).toBe('signing');
		});
	});

	describe('revoking', () => {
		it('takes a published key out of the key set and the key list at once', async () => {
			const { cookie, groupId } = await administrator('plain');
			const bucket = await ownedBucket(groupId);
			const key = await generate(bucket._id, cookie, 'ES256');

			const res = await revoke(bucket._id, cookie, key.kid);

			expect(res.status).toBe(200);
			expect(shaped(Revocation, res.body)).toEqual({
				kid: key.kid,
				state: 'revoked',
				replacementGenerated: false
			});
			expect(await publishedKids(present(bucket.slug, 'slug'))).not.toContain(
				key.kid
			);
			expect(await states(bucket._id, cookie)).not.toHaveProperty(key.kid);
		});

		it('makes the ready key of its algorithm sign when the signer is revoked', async () => {
			const { cookie, groupId } = await administrator('plain');
			const bucket = await ownedBucket(groupId);
			const [initial] = await listed(bucket._id, cookie);
			const ready = await generate(bucket._id, cookie, 'RS256');
			later(KEY_PUBLICATION_SECONDS + 1);

			const res = await revoke(bucket._id, cookie, initial.kid);

			expect(shaped(Revocation, res.body)).toMatchObject({
				replacement: ready.kid,
				replacementGenerated: false
			});
			expect(await states(bucket._id, cookie)).toEqual({
				[ready.kid]: 'signing'
			});
		});

		it('makes a newly generated key sign at once when the signer is revoked and no key is ready', async () => {
			const { cookie, groupId } = await administrator('plain');
			const bucket = await ownedBucket(groupId);
			const [initial] = await listed(bucket._id, cookie);
			const waiting = await generate(bucket._id, cookie, 'RS256');

			const res = await revoke(bucket._id, cookie, initial.kid);

			const revocation = shaped(Revocation, res.body);
			expect(revocation.replacementGenerated).toBe(true);
			const replacement = present(revocation.replacement, 'replacement');
			expect(await states(bucket._id, cookie)).toEqual({
				[waiting.kid]: 'published',
				[replacement]: 'signing'
			});
		});

		it('records the revocation of a signer once, naming the revoked key and the one now signing', async () => {
			const { cookie, groupId, userId } = await administrator('plain');
			const bucket = await ownedBucket(groupId);
			const [initial] = await listed(bucket._id, cookie);

			const revocation = shaped(
				Revocation,
				(await revoke(bucket._id, cookie, initial.kid)).body
			);

			const replacement = present(revocation.replacement, 'replacement');
			const entries = await entriesOf(userId, 'bucket.key.revoke');
			expect(
				entries.map((entry) => [entry.targetId, entry.kid, entry.keys])
			).toEqual([
				[
					bucket._id,
					initial.kid,
					{ revoked: initial.kid, signing: replacement, generated: replacement }
				]
			]);
		});

		/*
		 * A revocation cannot be undone, so the operator has to name the key they mean. Checked before anything
		 * is recorded: a revocation that does not name it is not one that happened.
		 */
		for (const [label, confirm] of [
			['without a confirmation', null],
			['whose confirmation names another key', 'not-this-key']
		] as const) {
			it(`is refused revoking a key ${label}, and nothing changes or is recorded`, async () => {
				const { cookie, groupId, userId } = await administrator('plain');
				const bucket = await ownedBucket(groupId);
				const key = await generate(bucket._id, cookie, 'ES256');

				const res = await revoke(bucket._id, cookie, key.kid, confirm);

				expect(res.status).toBe(422);
				expect(res.body.reason).toBe('confirmation_mismatch');
				expect((await states(bucket._id, cookie))[key.kid]).toBe('published');
				expect(await entriesOf(userId, 'bucket.key.revoke')).toEqual([]);
			});
		}

		it('is refused revoking a key already revoked', async () => {
			const { cookie, groupId } = await administrator('plain');
			const bucket = await ownedBucket(groupId);
			const key = await generate(bucket._id, cookie, 'ES256');
			await revoke(bucket._id, cookie, key.kid);

			const res = await revoke(bucket._id, cookie, key.kid);

			expect(res.status).toBe(409);
			expect(res.body.reason).toBe('already_revoked');
		});

		it('is refused promoting a revoked key', async () => {
			const { cookie, groupId } = await administrator('plain');
			const bucket = await ownedBucket(groupId);
			const key = await generate(bucket._id, cookie, 'RS256');
			later(KEY_PUBLICATION_SECONDS + 1);
			await revoke(bucket._id, cookie, key.kid);

			const res = await call(
				'POST',
				`/admin/api/projects/${bucket._id}/keys/${encodeURIComponent(key.kid)}/promote`,
				cookie
			);

			expect(res.status).toBe(404);
		});
	});

	/*
	 * Through a real token: a machine client of a tenant bucket holds a JWT access token its signer signed,
	 * and a resource server verifies tokens against the bucket's published key set — the verification a
	 * revocation has to end.
	 */
	describe('a token signed by a key that is then revoked', () => {
		const { slug, pathOrigin, pathClient } = addresses('revoke');
		let bucketId = '';
		let before = '';
		let revocation = { kid: '', replacement: '' };

		async function verifies(token: string) {
			const keys = await publishedKeys(`${pathOrigin}/jwks`);
			try {
				await jwtVerify(token, createLocalJWKSet(keys));
				return true;
			} catch {
				return false;
			}
		}

		beforeAll(async () => {
			forgetBucketAddresses();
			bucketId = await tenant({ slug }, pathClient);
			before = await machineToken(pathOrigin, pathClient);
			// Otherwise "no longer verifies" below would pass for a token that never did.
			if (!(await verifies(before))) {
				throw new Error('the token did not verify before the revocation');
			}
			const { cookie } = await administrator('super');
			const signer = present(
				decodeProtectedHeader(before).kid,
				'the signing kid'
			);
			const res = shaped(
				Revocation,
				(await revoke(bucketId, cookie, signer)).body
			);
			revocation = {
				kid: res.kid,
				replacement: present(res.replacement, 'replacement')
			};
		});

		it('no longer verifies against the bucket key set', async () => {
			expect(await verifies(before)).toBe(false);
		});

		it('is absent from the keys the bucket verifies with', async () => {
			const bucket = present(
				await getBucketStore().find(bucketId),
				'the tenant bucket'
			);
			const kids = [...(await keysFor(bucket)).verification].map((key) =>
				String(key.kid)
			);

			expect(kids).not.toContain(revocation.kid);
		});

		it('is followed by tokens the replacing key signs, which verify', async () => {
			const after = await machineToken(pathOrigin, pathClient);

			expect(decodeProtectedHeader(after).kid).toBe(revocation.replacement);
			expect(await verifies(after)).toBe(true);
		});
	});
});
