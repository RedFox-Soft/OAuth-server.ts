import {
	getActivityStore,
	getBucketGroupStore,
	getBucketKeysStore,
	getBucketStore,
	getGroupStore,
	getUserStore
} from '../../adapters/index.js';
import type { BucketDeletion, UserBucket } from '../../adapters/types.js';
import { now } from '../../activity/clock.js';
import { BUCKET_PURGE_CLAIM_MS } from '../../consts/bucket_deletion.js';
import { RETENTION_ACTOR } from '../../consts/admin_audit_routes.js';
import { cascadeForAccount } from '../../helpers/cascade.js';
import { emailScopedId } from '../../helpers/email_scoped_id.js';
import { invalidateBucketKeys } from '../../keys/issuer_keys.js';
import { destroyConnectionsOf } from '../../provisioning/service.js';
import {
	recordAdminAudit,
	recordSystemAudit,
	type AuditDetail
} from '../audit/record.js';
import { AdminError, type AdminContext } from '../auth/rbac.js';
import { forgetBucketAddresses } from '../auth/bucketAddress.js';
import { groupLabel } from '../groups/label.js';

/* Who is destroying the bucket: an administrator's Delete now, or the server when the thirty days ran out. */
export type DestroyingActor =
	{ kind: 'admin'; ctx: AdminContext } | { kind: 'server' };

export type DestroyOutcome =
	| { claimed: false }
	| { claimed: true; endUsersDestroyed: number; failedAreas: string[] };

/*
 * Destroys a bucket scheduled for deletion, and everything it holds (specs/090 R10) — the one procedure both
 * Delete now and the background pass run, so the two destroy exactly what a deletion destroyed before a
 * deletion was a schedule, and keep exactly what it kept.
 *
 * Only the holder of the claim proceeds: two server instances, or a pass racing an administrator, cannot
 * both destroy. `due` holds the pass to the date (`at`, now unless a caller names it); Delete now is not held
 * to it. An answer of `claimed: false`
 * means somebody else holds the bucket, or it is no longer scheduled, or — for the pass — not yet due.
 *
 * The bucket record goes LAST. A failure part-way leaves the bucket, still scheduled and still answering
 * nothing, for the next pass to find once the claim lapses and finish; destroyed first, as the route once
 * did, it took with it the only thing that could find the keys, connections and groups still left behind.
 */
export async function destroyBucket(
	bucket: Pick<UserBucket, '_id'>,
	actor: DestroyingActor,
	opts: { due: boolean; at?: Date }
): Promise<DestroyOutcome> {
	const id = bucket._id;
	const at = opts.at ?? now();
	const until = new Date(at.getTime() + BUCKET_PURGE_CLAIM_MS);
	const claimed = await getBucketStore().claimPurge(id, at, until, {
		due: opts.due
	});
	if (!claimed?.deletion) return { claimed: false };

	/*
	 * A destruction that throws gives its claim back, so the administrator's next Delete now — or the next
	 * pass — starts at once instead of being told for fifteen minutes that the bucket is already being deleted.
	 * The claim exists to keep two destructions from running together; once this one has stopped, it protects
	 * nothing. Only a process that dies mid-way leaves it to lapse, which is what the lapse is for.
	 */
	try {
		return await destroyClaimed(claimed, claimed.deletion, actor);
	} catch (error) {
		await getBucketStore()
			.releasePurge(id, until)
			.catch((release: unknown) => {
				console.error('bucket purge: could not release the claim; it lapses', {
					bucketId: id,
					error: release
				});
			});
		throw error;
	}
}

async function destroyClaimed(
	claimed: UserBucket,
	deletion: BucketDeletion,
	actor: DestroyingActor
): Promise<DestroyOutcome> {
	const id = claimed._id;

	const store = getUserStore(id);
	/*
	 * `list()` does not filter, which is what makes a deactivated account count — deactivation is a sign-in
	 * decision, not absence, and the account is still there to be destroyed.
	 */
	const accounts = await store.list();

	/*
	 * One entry carrying a count, never one per account: a bucket-sized deletion writing a row per person
	 * would bury everything else an operator needs to investigate, and would say nothing the bucket's
	 * identity does not already say — a cascade is all-or-nothing over what it held. After the claim and
	 * before the destruction, by the trail's own contract; and once, however often a failed destruction is
	 * retried — the entry is marked written on the claim, which a later claim keeps.
	 */
	if (!deletion.purge?.recordedAt) {
		const detail: AuditDetail = {
			...(accounts.length > 0
				? { cascade: { endusers: accounts.length } }
				: {}),
			/* So the group that owned it reads the destruction in its own trail. */
			ownerGroupId: claimed.ownerGroupId,
			scheduledAt: deletion.scheduledAt
		};
		if (actor.kind === 'admin') {
			await recordAdminAudit(actor.ctx, 'bucket.purge', id, detail);
		} else {
			await recordSystemAudit(RETENTION_ACTOR, 'bucket.purge', id, detail);
		}
		await getBucketStore().markPurgeRecorded(id, now());
	}

	/*
	 * The bucket's usage history is kept (specs/076, FR-011): its tombstone first, before anything is
	 * destroyed, because without it a deleted bucket's figures could never be listed again — no loader
	 * finds the bucket once it is gone. If it cannot be written the deletion does not begin, which is the
	 * one moment refusing is clean; a repeated request finds the tombstone and proceeds. The open month and
	 * day are frozen in the same call, best effort — the closer catches up.
	 *
	 * Neither activity area is swept below, deliberately: they hold evidence of how many people used the
	 * bucket, and deleting the bucket must not erase it.
	 *
	 * The owner goes on the tombstone too (specs/077): the usage overview names a deleted bucket's customer
	 * from it once the group itself may be gone. A group cannot be deleted while it owns a bucket, so it is
	 * found here; if it somehow is not, its id stands in for its name rather than the deletion being refused
	 * over a label.
	 */
	try {
		const owner = await getGroupStore().find(claimed.ownerGroupId);
		await getActivityStore().retire(
			{
				_id: claimed._id,
				name: claimed.name,
				...(claimed.slug === undefined ? {} : { slug: claimed.slug }),
				createdAt: claimed.createdAt
			},
			{
				groupId: claimed.ownerGroupId,
				label: owner ? groupLabel(owner) : claimed.ownerGroupId
			},
			now()
		);
	} catch (error) {
		console.error("activity: could not keep a deleted bucket's history", {
			bucketId: id,
			error
		});
		throw new AdminError(
			500,
			"the bucket's usage history could not be kept; nothing was deleted"
		);
	}

	/*
	 * The email is read before the row goes, per account, because the email-scoped areas are addressed by
	 * `${bucketId}:${email}` and nothing else records it. Destroy first and those records are unreachable —
	 * skipped in silence, with no error anywhere to notice. The already-computed id in `cascadeForAccount`'s
	 * signature is what makes that ordering impossible to get wrong here.
	 */
	const failedAreas: string[] = [];
	for (const account of accounts) {
		const scopedId = account.email ? emailScopedId(id, account.email) : null;
		await store.destroy(account._id);
		const swept = await cascadeForAccount(account._id, scopedId);
		failedAreas.push(...swept.failedAreas);
	}

	/*
	 * Its keys go with it. They sign for an issuer that no longer exists, and leaving the private halves
	 * behind would keep key material nobody can manage any more.
	 */
	await getBucketKeysStore().destroyByBucket(id);
	invalidateBucketKeys(id);
	/*
	 * Its SCIM provisioning connections go too, and every token they obtained with them: a token outliving
	 * its bucket would fail at the SCIM principal anyway, but a customer's directory should see its
	 * credential refused at the token endpoint, not answered with a token for nothing.
	 */
	for (const swept of await destroyConnectionsOf(id)) {
		failedAreas.push(...swept.failedAreas);
	}
	/* Its groups and every membership in them; nothing outside the bucket refers to either. */
	await getBucketGroupStore().destroyByBucket(id);
	/* The half that was missing: without this a deleted bucket left its `user_<bucket>` area behind for
	 * good, indexes and all. Safe here and only here, because the loop above emptied it. */
	await store.destroyArea();

	await getBucketStore().destroy(id);
	/* The address is gone; a cached entry would keep answering for a bucket that no longer exists. */
	forgetBucketAddresses();

	return {
		claimed: true,
		endUsersDestroyed: accounts.length,
		failedAreas: [...new Set(failedAreas)]
	};
}
