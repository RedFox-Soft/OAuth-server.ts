import { getUserStore } from '../adapters/index.js';
import type { UserBucket } from '../adapters/types.js';
import {
	EndUserError,
	removeEndUser,
	revokeEndUserAccess,
	updateEndUser,
	type EndUserActor,
	type RecordChange
} from './service.js';

/*
 * One act applied to a selection of people (specs/089). Each person goes through the single act's own service
 * function, so the checks, the cascade and the audit entry are the single act's — nothing here decides what
 * an act does to a person, only whether it applies to them at all.
 */

export type BulkAct = 'deactivate' | 'activate' | 'sign-out' | 'delete';

export type BulkSkipReason =
	'provisioned' | 'already_active' | 'already_inactive' | 'not_found';

export interface BulkResult {
	id: string;
	outcome: 'changed' | 'skipped' | 'failed';
	/* A skip's reason, or what made a failure fail. */
	reason?: string;
	/* The areas whose records survived an access sweep or a deletion that otherwise went through. */
	failedAreas?: readonly string[];
}

const ADMIN: EndUserActor = { kind: 'admin' };

/*
 * Whether the act applies to this person, decided from their record before anything is recorded: a skip is not
 * an attempt and leaves no entry. A directory's people are skipped by every act an administrator may not do to
 * them — sign-out ends access and edits nothing the directory owns, so it skips nobody.
 */
function skipFor(
	act: BulkAct,
	user: { active: boolean; provisionedBy?: string }
): BulkSkipReason | null {
	if (act === 'sign-out') return null;
	if (user.provisionedBy !== undefined) return 'provisioned';
	if (act === 'deactivate' && !user.active) return 'already_inactive';
	if (act === 'activate' && user.active) return 'already_active';
	return null;
}

/* Runs the single act for one person and reports any access that outlived it. */
async function applyOne(
	bucket: UserBucket,
	act: BulkAct,
	id: string,
	record: RecordChange
): Promise<readonly string[]> {
	switch (act) {
		case 'deactivate':
		case 'activate': {
			const { revoked } = await updateEndUser(
				bucket,
				ADMIN,
				id,
				{ active: act === 'activate' },
				record
			);
			return revoked?.failedAreas ?? [];
		}
		case 'sign-out': {
			const { revoked } = await revokeEndUserAccess(bucket, id, record);
			return revoked?.failedAreas ?? [];
		}
		case 'delete':
			return (await removeEndUser(bucket, ADMIN, id, record)).failedAreas;
	}
}

/*
 * The ids are de-duplicated and handled one after another, in the order given: a hundred deletions run in
 * parallel would put a hundred cascades on the datastore at once. One person's failure is that person's
 * result, never the request's, so the answer always says what happened to everyone and a repeat is harmless —
 * those already done are skipped or not found.
 */
export async function applyBulk(
	bucket: UserBucket,
	act: BulkAct,
	userIds: readonly string[],
	recordFor: (id: string) => Promise<unknown>
): Promise<BulkResult[]> {
	const results: BulkResult[] = [];
	for (const id of new Set(userIds)) {
		const user = await getUserStore(bucket._id).find(id);
		if (!user) {
			results.push({ id, outcome: 'skipped', reason: 'not_found' });
			continue;
		}
		const skip = skipFor(act, user);
		if (skip) {
			results.push({ id, outcome: 'skipped', reason: skip });
			continue;
		}
		try {
			const failedAreas = await applyOne(bucket, act, id, () => recordFor(id));
			results.push(
				failedAreas.length > 0
					? {
							id,
							outcome: 'failed',
							reason: `done, but their records survive in: ${failedAreas.join(', ')}`,
							failedAreas
						}
					: { id, outcome: 'changed' }
			);
		} catch (error) {
			if (error instanceof EndUserError && error.status === 404) {
				results.push({ id, outcome: 'skipped', reason: 'not_found' });
				continue;
			}
			results.push({
				id,
				outcome: 'failed',
				reason: error instanceof Error ? error.message : String(error)
			});
		}
	}
	return results;
}
