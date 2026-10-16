import { describe, it, expect, beforeAll } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import type { UserBucket } from 'lib/adapters/types.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import type { FederationProvider } from 'lib/federation/types.ts';
import { shaped } from 'test/shape.js';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { admin } from '../provisioning/helpers.ts';
import { provider } from './harness.ts';

const GOOGLE = 'https://accounts.google.com';
const microsoft = (tenant: string) =>
	`https://login.microsoftonline.com/${tenant}/v2.0`;

const Listed = Type.Array(
	Type.Object({ id: Type.String(), signInWarnings: Type.Array(Type.String()) })
);
const Detail = Type.Object({ warnings: Type.Array(Type.String()) });

async function bucketWith(
	federation: FederationProvider[]
): Promise<UserBucket> {
	return getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: `brand-${Math.random()}`,
		slug: `brand-${Math.random().toString(36).slice(2, 10)}`,
		federation
	});
}

async function listed(bucket: UserBucket, cookie: string) {
	const reply = await admin(
		'GET',
		`/admin/api/projects/${bucket._id}/federation`,
		cookie
	);
	expect(reply.status).toBe(200);
	return Object.fromEntries(
		shaped(Listed, reply.body).map((p) => [p.id, p.signInWarnings])
	);
}

async function warningsOf(bucket: UserBucket, id: string, cookie: string) {
	const reply = await admin(
		'GET',
		`/admin/api/projects/${bucket._id}/federation/${id}`,
		cookie
	);
	expect(reply.status).toBe(200);
	return shaped(Detail, reply.body).warnings;
}

/**
 * @proves An administrator, or an agent reading the same routes, is warned when a project's providers would put
 * two identical brand buttons on its sign-in page, or a button that reads like a brand without being one — and
 * is not warned about two Microsoft organisations, which is the ordinary way to connect two.
 */
describe('providers that would confuse people on the sign-in page', () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'brand_warnings' });
		await ensureAdminSeed();
		cookie = await adminCookie();
	});

	it('warns on both of two enabled Google connections', async () => {
		const bucket = await bucketWith([
			provider(GOOGLE, { id: 'google', displayName: 'Google' }),
			provider(GOOGLE, { id: 'google-2', displayName: 'Google (new)' })
		]);

		expect(await listed(bucket, cookie)).toEqual({
			google: ['duplicate_brand'],
			'google-2': ['duplicate_brand']
		});
		expect(await warningsOf(bucket, 'google-2', cookie)).toContain(
			'duplicate_brand'
		);
	});

	it('does not warn about a second Google connection that is switched off', async () => {
		const bucket = await bucketWith([
			provider(GOOGLE, { id: 'google', displayName: 'Google' }),
			provider(GOOGLE, { id: 'old', displayName: 'Old', enabled: false })
		]);

		expect(await listed(bucket, cookie)).toEqual({ google: [], old: [] });
	});

	it('does not warn about two Microsoft organisations', async () => {
		const bucket = await bucketWith([
			provider(microsoft('contoso.example'), { id: 'contoso' }),
			provider(microsoft('fabrikam.example'), { id: 'fabrikam' })
		]);

		expect(await listed(bucket, cookie)).toEqual({ contoso: [], fabrikam: [] });
		expect(await warningsOf(bucket, 'contoso', cookie)).not.toContain(
			'duplicate_brand'
		);
	});

	it('warns on a provider it does not recognise that is named like a brand', async () => {
		const bucket = await bucketWith([
			provider('https://sso.example.test', {
				id: 'github-ish',
				displayName: ' github '
			})
		]);

		expect(await listed(bucket, cookie)).toEqual({
			'github-ish': ['named_like_brand']
		});
		expect(await warningsOf(bucket, 'github-ish', cookie)).toContain(
			'named_like_brand'
		);
	});
});
