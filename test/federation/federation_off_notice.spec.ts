import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import type { UserBucket } from 'lib/adapters/types.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { loginOptionsForBucket } from 'lib/interactions/loginOptions.ts';
import { shaped } from 'test/shape.js';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { admin } from '../provisioning/helpers.ts';
import { provider } from './harness.ts';

const Listed = Type.Array(
	Type.Object({ id: Type.String(), onSignInPage: Type.Boolean() })
);
const Detail = Type.Object({ warnings: Type.Array(Type.String()) });

async function bucketWith(
	providers: { id: string; enabled: boolean }[]
): Promise<UserBucket> {
	return getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: `off-${Math.random()}`,
		slug: `off-${Math.random().toString(36).slice(2, 10)}`,
		federation: providers.map(({ id, enabled }) =>
			provider(`https://${id}.idp.test`, { id, displayName: id, enabled })
		)
	});
}

async function listed(bucket: UserBucket, cookie: string) {
	const reply = await admin(
		'GET',
		`/admin/api/projects/${bucket._id}/federation`,
		cookie
	);
	return Object.fromEntries(
		shaped(Listed, reply.body).map((p) => [p.id, p.onSignInPage])
	);
}

async function warningsOf(bucket: UserBucket, id: string, cookie: string) {
	const reply = await admin(
		'GET',
		`/admin/api/projects/${bucket._id}/federation/${id}`,
		cookie
	);
	return shaped(Detail, reply.body).warnings;
}

async function onPage(bucket: UserBucket) {
	return (await loginOptionsForBucket(bucket._id)).providers.map((p) => p.id);
}

/**
 * @proves An administrator, or an agent reading the same routes, learns that a connected provider is missing
 * from the sign-in page because sign-in through providers is switched off on the instance, and the answer
 * agrees with what the sign-in page shows.
 */
describe('a provider whose button the instance switch hides', () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'federation_off_notice' });
		await ensureAdminSeed();
	});

	beforeEach(async () => {
		cookie = await adminCookie();
	});

	it('says an enabled provider is not on the sign-in page while federation is off, and why', async () => {
		const bucket = await bucketWith([{ id: 'acme', enabled: true }]);

		expect(await listed(bucket, cookie)).toEqual({ acme: false });
		expect(await warningsOf(bucket, 'acme', cookie)).toContain(
			'federation_off'
		);
		expect(await onPage(bucket)).toEqual([]);
	});

	it('says it is on the sign-in page once federation is on, with no warning', async () => {
		const bucket = await bucketWith([{ id: 'acme', enabled: true }]);
		ApplicationConfig['federation.enabled'] = true;
		try {
			expect(await listed(bucket, cookie)).toEqual({ acme: true });
			expect(await warningsOf(bucket, 'acme', cookie)).not.toContain(
				'federation_off'
			);
			expect(await onPage(bucket)).toEqual(['acme']);
		} finally {
			ApplicationConfig['federation.enabled'] = false;
		}
	});

	it('blames a disabled provider’s own switch, not the instance', async () => {
		const bucket = await bucketWith([{ id: 'acme', enabled: false }]);

		expect(await listed(bucket, cookie)).toEqual({ acme: false });
		expect(await warningsOf(bucket, 'acme', cookie)).not.toContain(
			'federation_off'
		);
	});
});
