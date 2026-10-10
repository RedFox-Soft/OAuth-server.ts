import { getGroupStore, getUserStore } from '../../adapters/index.js';
import type { Group } from '../../adapters/types.js';
import {
	customerKey,
	type CustomerDetails,
	type CustomerRef
} from '../../activity/overview.js';
import {
	ADMIN_BUCKET_ID,
	SYSTEM_GROUP_NAME,
	UNASSIGNED_GROUP_ID
} from '../consts.js';
import { groupLabel } from '../groups/label.js';

/*
 * Who each bucket in the usage overview belongs to (specs/077). Read from the live group every time, so a
 * renamed group shows its new name; only a deleted bucket whose group is gone too falls back to what its
 * tombstone recorded.
 */

export interface CustomerSource {
	bucketId: string;
	/* The live bucket's owner, or the one its tombstone recorded; absent for a tombstone written before 077. */
	ownerGroupId?: string;
	recordedLabel?: string;
}

export const UNKNOWN_CUSTOMER: CustomerRef = {
	groupId: null,
	label: 'Unknown',
	kind: null,
	exists: false
};

function refOf(group: Group): CustomerRef {
	return {
		groupId: group._id,
		label: groupLabel(group),
		kind: group.kind,
		exists: true
	};
}

/*
 * The holding group owns the reserved buckets, and on an instance never provisioned (a test, mostly) it may
 * not be stored; it is still the System group, not a vanished one.
 */
const SYSTEM: CustomerRef = {
	groupId: UNASSIGNED_GROUP_ID,
	label: SYSTEM_GROUP_NAME,
	kind: 'system',
	exists: true
};

export async function resolveCustomers(
	sources: readonly CustomerSource[]
): Promise<{
	refs: Map<string, CustomerRef>;
	details: Map<string, CustomerDetails>;
}> {
	const groups = new Map(
		(await getGroupStore().list()).map((group) => [group._id, group])
	);
	const refs = new Map<string, CustomerRef>();
	const owning = new Map<string, Group>();
	for (const source of sources) {
		const group =
			source.ownerGroupId === undefined
				? undefined
				: groups.get(source.ownerGroupId);
		if (group) {
			refs.set(source.bucketId, refOf(group));
			owning.set(group._id, group);
		} else if (source.ownerGroupId === UNASSIGNED_GROUP_ID) {
			refs.set(source.bucketId, SYSTEM);
		} else if (source.ownerGroupId !== undefined) {
			refs.set(source.bucketId, {
				groupId: source.ownerGroupId,
				label: source.recordedLabel ?? source.ownerGroupId,
				kind: null,
				exists: false
			});
		} else {
			refs.set(source.bucketId, UNKNOWN_CUSTOMER);
		}
	}
	return { refs, details: await detailsOf([...owning.values()]) };
}

/*
 * A customer's contacts are the people who decide for it: its owners, not its plain members. Administrators,
 * not end users — the overview names nobody who was counted.
 */
async function detailsOf(
	groups: readonly Group[]
): Promise<Map<string, CustomerDetails>> {
	const ownerIds = [
		...new Set(
			groups.flatMap((group) =>
				group.members
					.filter((member) => member.role === 'owner')
					.map((member) => member.userId)
			)
		)
	];
	const emails = new Map(
		ownerIds.length === 0
			? []
			: (await getUserStore(ADMIN_BUCKET_ID).findMany(ownerIds)).map((user) => [
					user._id,
					user.email
				])
	);
	const details = new Map<string, CustomerDetails>();
	for (const group of groups) {
		details.set(customerKey(refOf(group)), {
			contacts: group.members
				.filter((member) => member.role === 'owner')
				.flatMap((member) => emails.get(member.userId) ?? []),
			memberCount: group.members.length
		});
	}
	return details;
}
