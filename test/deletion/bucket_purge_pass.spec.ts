import { beforeAll, describe, expect, it, spyOn } from 'bun:test';

import bootstrap from '../test_helper.js';
import {
	adminAuditStore,
	getActivityStore,
	getBucketGroupStore,
	getBucketKeysStore,
	getBucketStore,
	getProvisioningConnectionStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { UserBucket } from 'lib/adapters/types.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { purgeDueBuckets } from 'lib/admin/buckets/purge_pass.ts';
import {
	BUCKET_PURGE_CLAIM_MS,
	purgeAtOf
} from 'lib/consts/bucket_deletion.ts';
import { RETENTION_ACTOR } from 'lib/consts/admin_audit_routes.ts';
import { ensureBucketKey } from 'lib/keys/issuer_keys.ts';
import nanoid from 'lib/helpers/nanoid.ts';

const DAY_MS = 24 * 60 * 60 * 1000;

function slugOf(): string {
	return `pp-${nanoid()
		.toLowerCase()
		.replace(/[^a-z0-9]/g, '')}`;
}

/* A bucket holding one account, a key, a group and a connection, scheduled `daysAgo` days ago. */
async function scheduledBucket(daysAgo: number, slug = slugOf()) {
	const bucket = await getBucketStore().create({
		name: `pass ${slug}`,
		slug,
		ownerGroupId: UNASSIGNED_GROUP_ID
	});
	const account = await getUserStore(bucket._id).create(`${slug}@x.io`, 'h');
	await ensureBucketKey(bucket._id);
	const group = await getBucketGroupStore().create({
		_id: nanoid(),
		bucketId: bucket._id,
		displayName: 'Staff'
	});
	const connection = await getProvisioningConnectionStore().create({
		_id: nanoid(),
		bucketId: bucket._id,
		displayName: 'Directory',
		enabled: true,
		providerId: 'none',
		correlation: { claim: 'oid', attribute: 'externalId' },
		emailTrust: 'untrusted',
		oauthCredential: null
	});
	const scheduledAt = new Date(Date.now() - daysAgo * DAY_MS);
	await getBucketStore().scheduleDeletion(bucket._id, {
		scheduledAt,
		purgeAt: purgeAtOf(scheduledAt),
		scheduledBy: { userId: 'an-administrator' }
	});
	return { bucket, account, group, connection };
}

async function purgeEntries(bucket: UserBucket) {
	return (await adminAuditStore.list({ targetId: bucket._id })).entries.filter(
		(entry) => entry.action === 'bucket.purge'
	);
}

/**
 * @proves A bucket whose thirty days of scheduled deletion have run out is destroyed by the server without
 * anyone asking — everything it held, except its usage history — and recorded once as the server's act in its
 * owner's trail; one not yet due is left alone; two passes at once destroy it once; and a destruction that
 * failed part-way is finished later without a second record.
 */
describe('the scheduled-deletion pass', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('destroys a due bucket and everything it held, keeping its usage history', async () => {
		const { bucket, account, group, connection } = await scheduledBucket(31);

		await purgeDueBuckets();

		expect(await getBucketStore().find(bucket._id)).toBeNull();
		expect(await getUserStore(bucket._id).find(account._id)).toBeNull();
		expect(await getBucketKeysStore().listByBucket(bucket._id)).toEqual([]);
		expect(await getBucketGroupStore().find(group._id)).toBeNull();
		expect(
			await getProvisioningConnectionStore().find(connection._id)
		).toBeNull();
		expect(await getActivityStore().tombstone(bucket._id)).not.toBeNull();
	});

	it('records the destruction once as the server’s, with the accounts it destroyed, for the owning group', async () => {
		const { bucket } = await scheduledBucket(31);

		await purgeDueBuckets();

		expect(
			(await purgeEntries(bucket)).map((e) => [
				e.actorId,
				e.ownerGroupId,
				e.cascade
			])
		).toEqual([[RETENTION_ACTOR, UNASSIGNED_GROUP_ID, { endusers: 1 }]]);
	});

	it('leaves a bucket whose date has not come', async () => {
		const { bucket, account } = await scheduledBucket(29);

		await purgeDueBuckets();

		expect(await getBucketStore().find(bucket._id)).not.toBeNull();
		expect(await getUserStore(bucket._id).find(account._id)).not.toBeNull();
	});

	it('destroys a bucket once and records it once when two passes run at the same moment', async () => {
		const { bucket } = await scheduledBucket(31);

		await Promise.all([purgeDueBuckets(), purgeDueBuckets()]);

		expect(await getBucketStore().find(bucket._id)).toBeNull();
		expect(await purgeEntries(bucket)).toHaveLength(1);
	});

	it('finishes a destruction that failed part-way, once its claim lapses, without recording it again', async () => {
		const { bucket, group } = await scheduledBucket(31);
		const log = spyOn(console, 'error').mockImplementation(() => undefined);
		const failing = spyOn(
			getBucketGroupStore(),
			'destroyByBucket'
		).mockRejectedValueOnce(new Error('the datastore went away'));

		await purgeDueBuckets();
		const leftBehind = await getBucketStore().find(bucket._id);
		failing.mockRestore();
		await purgeDueBuckets(new Date(Date.now() + BUCKET_PURGE_CLAIM_MS + 1000));
		log.mockRestore();

		expect(leftBehind?.deletion).toBeDefined();
		expect(await getBucketStore().find(bucket._id)).toBeNull();
		expect(await getBucketGroupStore().find(group._id)).toBeNull();
		expect(await purgeEntries(bucket)).toHaveLength(1);
	});

	it('frees the address for a new bucket', async () => {
		const slug = slugOf();
		await scheduledBucket(31, slug);

		await purgeDueBuckets();

		expect(await getBucketStore().findBySlug(slug)).toBeNull();
	});
});
