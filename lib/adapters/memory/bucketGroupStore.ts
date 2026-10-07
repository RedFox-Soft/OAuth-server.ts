import {
	MAX_END_USER_PAGE,
	type BucketGroup,
	type BucketGroupChange,
	type BucketGroupFilter,
	type BucketGroupMember,
	type BucketGroupQueryResult,
	type BucketGroupStoreInstance,
	type EndUserPage,
	type NewBucketGroup
} from '../types.js';
import { UniqueValueTaken } from '../conflicts.js';
import {
	bucketGroupKeysOf,
	clampPage,
	displayNameKeyOf,
	externalIdKeyOf,
	membershipIdOf
} from '../end_user_keys.js';

function byId<T extends { _id: string }>(a: T, b: T): number {
	return a._id < b._id ? -1 : a._id > b._id ? 1 : 0;
}

/*
 * In-memory bucket groups and their memberships. Both unique keys are enforced by scan, so the naming rules
 * are observable in the default test run; a change is applied synchronously, so it is atomic here by
 * construction — the datastores' behaviour is what `bucket-group-change-atomicity` declares.
 */
export class BucketGroupStore implements BucketGroupStoreInstance {
	private groups = new Map<string, BucketGroup>();
	private members = new Map<string, BucketGroupMember>();

	private takenBy(candidate: BucketGroup): UniqueValueTaken | null {
		for (const other of this.groups.values()) {
			if (other._id === candidate._id) continue;
			if (other.displayNameKey === candidate.displayNameKey) {
				return new UniqueValueTaken('displayName', candidate.displayName);
			}
			if (
				candidate.externalIdKey !== undefined &&
				other.externalIdKey === candidate.externalIdKey
			) {
				return new UniqueValueTaken('externalId', candidate.externalId ?? '');
			}
		}
		return null;
	}

	private addMembers(group: BucketGroup, userIds: string[], now: Date): void {
		for (const userId of userIds) {
			const _id = membershipIdOf(group._id, userId);
			if (this.members.has(_id)) continue;
			this.members.set(_id, {
				_id,
				groupId: group._id,
				userId,
				bucketId: group.bucketId,
				createdAt: now
			});
		}
	}

	async create(
		data: NewBucketGroup,
		memberIds: string[] = []
	): Promise<BucketGroup> {
		const now = new Date();
		const group = withoutUndefined({
			...data,
			...bucketGroupKeysOf(data),
			createdAt: now,
			updatedAt: now
		});
		const taken = this.takenBy(group);
		if (taken) throw taken;
		this.groups.set(group._id, group);
		this.addMembers(group, memberIds, now);
		return structuredClone(group);
	}

	async find(id: string): Promise<BucketGroup | null> {
		const found = this.groups.get(id);
		return found ? structuredClone(found) : null;
	}

	async findMany(ids: string[]): Promise<BucketGroup[]> {
		return ids
			.slice(0, MAX_END_USER_PAGE)
			.map((id) => this.groups.get(id))
			.filter((g): g is BucketGroup => g !== undefined)
			.map((g) => structuredClone(g));
	}

	async query(
		filter: BucketGroupFilter,
		page: EndUserPage
	): Promise<BucketGroupQueryResult> {
		const { offset, limit } = clampPage(page, MAX_END_USER_PAGE);
		const nameKey =
			filter.displayName === undefined
				? undefined
				: displayNameKeyOf(filter.bucketId, filter.displayName);
		const memberOf =
			filter.member === undefined
				? undefined
				: new Set(
						[...this.members.values()]
							.filter(
								(m) =>
									m.bucketId === filter.bucketId && m.userId === filter.member
							)
							.map((m) => m.groupId)
					);
		const matches = [...this.groups.values()]
			.filter(
				(g) =>
					g.bucketId === filter.bucketId &&
					(filter.provisionedBy === undefined ||
						g.provisionedBy === filter.provisionedBy) &&
					(filter.id === undefined || g._id === filter.id) &&
					(nameKey === undefined || g.displayNameKey === nameKey) &&
					/* An external identifier means something only within a connection; without one nothing matches. */
					(filter.externalId === undefined ||
						(filter.provisionedBy !== undefined &&
							g.externalIdKey ===
								externalIdKeyOf(filter.provisionedBy, filter.externalId))) &&
					(memberOf === undefined || memberOf.has(g._id))
			)
			.sort(byId);
		return {
			groups: matches
				.slice(offset, offset + limit)
				.map((g) => structuredClone(g)),
			totalResults: matches.length
		};
	}

	async memberIds(groupId: string, page?: EndUserPage): Promise<string[]> {
		const ids = [...this.members.values()]
			.filter((m) => m.groupId === groupId)
			.map((m) => m.userId)
			.sort();
		if (!page) return ids;
		const { offset, limit } = clampPage(page, MAX_END_USER_PAGE);
		return ids.slice(offset, offset + limit);
	}

	async memberCount(groupId: string): Promise<number> {
		let count = 0;
		for (const m of this.members.values()) if (m.groupId === groupId) count++;
		return count;
	}

	async groupIdsOf(
		bucketId: string,
		userIds: string[],
		provisionedBy?: string
	): Promise<Map<string, string[]>> {
		const wanted = new Set(userIds);
		const result = new Map<string, string[]>(userIds.map((id) => [id, []]));
		for (const m of this.members.values()) {
			if (m.bucketId !== bucketId || !wanted.has(m.userId)) continue;
			if (
				provisionedBy !== undefined &&
				this.groups.get(m.groupId)?.provisionedBy !== provisionedBy
			) {
				continue;
			}
			result.get(m.userId)?.push(m.groupId);
		}
		for (const ids of result.values()) ids.sort();
		return result;
	}

	async change(
		groupId: string,
		change: BucketGroupChange
	): Promise<BucketGroup | null> {
		const current = this.groups.get(groupId);
		if (!current) return null;
		const now = new Date();
		const merged = { ...current, ...change.attributes, updatedAt: now };
		const next = withoutUndefined({ ...merged, ...bucketGroupKeysOf(merged) });
		const taken = this.takenBy(next);
		if (taken) throw taken;
		this.groups.set(groupId, next);
		this.addMembers(next, change.add ?? [], now);
		for (const userId of change.remove ?? []) {
			this.members.delete(membershipIdOf(groupId, userId));
		}
		return structuredClone(next);
	}

	async removeUser(bucketId: string, userId: string): Promise<void> {
		for (const [id, m] of this.members) {
			if (m.bucketId === bucketId && m.userId === userId)
				this.members.delete(id);
		}
	}

	async destroy(id: string): Promise<void> {
		for (const [mid, m] of this.members) {
			if (m.groupId === id) this.members.delete(mid);
		}
		this.groups.delete(id);
	}

	async destroyByBucket(bucketId: string): Promise<void> {
		for (const [mid, m] of this.members) {
			if (m.bucketId === bucketId) this.members.delete(mid);
		}
		for (const [id, g] of this.groups) {
			if (g.bucketId === bucketId) this.groups.delete(id);
		}
	}
}

/* An undefined member means "absent"; leaving it on the record would make it a value the unique scan sees. */
function withoutUndefined<T extends object>(record: T): T {
	const copy = { ...record };
	for (const [field, value] of Object.entries(copy)) {
		if (value === undefined) Reflect.deleteProperty(copy, field);
	}
	return copy;
}
