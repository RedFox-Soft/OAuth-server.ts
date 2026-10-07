import type { ClientSession } from 'mongodb';
import { client, db, supportsTransactions } from './db.js';
import { ABSENT_UNDEFINED } from './write_options.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import { UniqueValueTaken } from '../conflicts.js';
import {
	bucketGroupKeysOf,
	clampPage,
	displayNameKeyOf,
	externalIdKeyOf,
	membershipIdOf
} from '../end_user_keys.js';
import {
	BucketGroup,
	MAX_END_USER_PAGE,
	type BucketGroupChange,
	type BucketGroupFilter,
	type BucketGroupMember,
	type BucketGroupQueryResult,
	type BucketGroupStoreInstance,
	type EndUserPage,
	type NewBucketGroup
} from '../types.js';

/* Which unique key a refused write collided on, from the index MongoDB names in the error. */
function takenFrom(
	error: unknown,
	group: Pick<BucketGroup, 'displayName' | 'externalId'>
): UniqueValueTaken | null {
	if (
		typeof error !== 'object' ||
		error === null ||
		!('code' in error) ||
		error.code !== 11000
	) {
		return null;
	}
	const pattern =
		'keyPattern' in error && typeof error.keyPattern === 'object'
			? Object.keys(error.keyPattern ?? {})
			: [];
	if (pattern.includes('displayNameKey')) {
		return new UniqueValueTaken('displayName', group.displayName);
	}
	if (pattern.includes('externalIdKey')) {
		return new UniqueValueTaken('externalId', group.externalId ?? '');
	}
	return null;
}

/*
 * Bucket groups and their membership records. Uniqueness is the unique indexes', not a read-then-write
 * check. A change runs in a transaction where the deployment has them (a replica set — Atlas, production
 * — or a sharded cluster); on a standalone `mongod` it runs as ordered writes, each idempotent, which is
 * the declared `bucket-group-change-atomicity` divergence.
 */
export class BucketGroupStore implements BucketGroupStoreInstance {
	private groups = db.collection<BucketGroup>(STORE_AREAS.bucketGroups);
	private members = db.collection<BucketGroupMember>(
		STORE_AREAS.bucketGroupMembers
	);

	private groupOf(found: unknown): BucketGroup | null {
		return found
			? documentOf(STORE_AREAS.bucketGroups, BucketGroup, found)
			: null;
	}

	/*
	 * Inserts that ignore a record already present: the `_id` is deterministic, so a duplicate means the
	 * membership exists, which is the outcome asked for.
	 */
	private async addMembers(
		group: Pick<BucketGroup, '_id' | 'bucketId'>,
		userIds: string[],
		session?: ClientSession
	): Promise<void> {
		if (userIds.length === 0) return;
		const createdAt = new Date();
		await this.members.bulkWrite(
			userIds.map((userId) => ({
				updateOne: {
					filter: { _id: membershipIdOf(group._id, userId) },
					update: {
						$setOnInsert: {
							groupId: group._id,
							userId,
							bucketId: group.bucketId,
							createdAt
						}
					},
					upsert: true
				}
			})),
			{ ordered: false, session }
		);
	}

	private async removeMembers(
		groupId: string,
		userIds: string[],
		session?: ClientSession
	): Promise<void> {
		if (userIds.length === 0) return;
		await this.members.deleteMany(
			{ _id: { $in: userIds.map((u) => membershipIdOf(groupId, u)) } },
			{ session }
		);
	}

	/* A transaction where the deployment has one; otherwise the same steps in order (see the class comment). */
	private async atomically<T>(
		steps: (session?: ClientSession) => Promise<T>
	): Promise<T> {
		if (!(await supportsTransactions())) return steps();
		const session = client.startSession();
		try {
			let result: T | undefined;
			await session.withTransaction(async () => {
				result = await steps(session);
			});
			return result as T; // withTransaction resolves only after the callback assigned it
		} finally {
			await session.endSession();
		}
	}

	async create(
		data: NewBucketGroup,
		memberIds: string[] = []
	): Promise<BucketGroup> {
		const now = new Date();
		const group: BucketGroup = {
			...data,
			...bucketGroupKeysOf(data),
			createdAt: now,
			updatedAt: now
		};
		try {
			await this.atomically(async (session) => {
				await this.groups.insertOne(group, { ...ABSENT_UNDEFINED, session });
				await this.addMembers(group, memberIds, session);
			});
		} catch (error) {
			const taken = takenFrom(error, group);
			if (taken) throw taken;
			throw error;
		}
		return group;
	}

	async find(id: string): Promise<BucketGroup | null> {
		return this.groupOf(await this.groups.findOne({ _id: id }));
	}

	async findMany(ids: string[]): Promise<BucketGroup[]> {
		if (ids.length === 0) return [];
		const found = await this.groups
			.find({ _id: { $in: ids.slice(0, MAX_END_USER_PAGE) } })
			.toArray();
		return found
			.map((g) => this.groupOf(g))
			.filter((g): g is BucketGroup => g !== null);
	}

	async query(
		filter: BucketGroupFilter,
		page: EndUserPage
	): Promise<BucketGroupQueryResult> {
		const { offset, limit } = clampPage(page, MAX_END_USER_PAGE);
		const stored: Record<string, unknown> = { bucketId: filter.bucketId };
		if (filter.provisionedBy !== undefined) {
			stored.provisionedBy = filter.provisionedBy;
		}
		if (filter.displayName !== undefined) {
			stored.displayNameKey = displayNameKeyOf(
				filter.bucketId,
				filter.displayName
			);
		}
		if (filter.externalId !== undefined) {
			/* An external identifier means something only within a connection; without one nothing matches. */
			stored.externalIdKey =
				filter.provisionedBy === undefined
					? null
					: externalIdKeyOf(filter.provisionedBy, filter.externalId);
		}
		if (filter.member !== undefined) {
			const memberOf = (
				await this.members
					.find(
						{ bucketId: filter.bucketId, userId: filter.member },
						{ projection: { groupId: 1 } }
					)
					.toArray()
			).map((m) => m.groupId);
			stored._id = {
				$in:
					filter.id === undefined
						? memberOf
						: memberOf.filter((id) => id === filter.id)
			};
		} else if (filter.id !== undefined) {
			stored._id = filter.id;
		}
		const [found, totalResults] = await Promise.all([
			limit === 0
				? Promise.resolve([])
				: this.groups
						.find(stored)
						.sort({ _id: 1 })
						.skip(offset)
						.limit(limit)
						.toArray(),
			this.groups.countDocuments(stored)
		]);
		return {
			groups: found
				.map((g) => this.groupOf(g))
				.filter((g): g is BucketGroup => g !== null),
			totalResults
		};
	}

	async memberIds(groupId: string, page?: EndUserPage): Promise<string[]> {
		let cursor = this.members
			.find({ groupId }, { projection: { userId: 1 } })
			.sort({ groupId: 1, userId: 1 });
		if (page) {
			const { offset, limit } = clampPage(page, MAX_END_USER_PAGE);
			if (limit === 0) return [];
			cursor = cursor.skip(offset).limit(limit);
		}
		return (await cursor.toArray()).map((m) => m.userId);
	}

	async memberCount(groupId: string): Promise<number> {
		return this.members.countDocuments({ groupId });
	}

	async groupIdsOf(
		bucketId: string,
		userIds: string[],
		provisionedBy?: string
	): Promise<Map<string, string[]>> {
		const result = new Map<string, string[]>(userIds.map((id) => [id, []]));
		if (userIds.length === 0) return result;
		const found = await this.members
			.find(
				{ bucketId, userId: { $in: userIds } },
				{ projection: { groupId: 1, userId: 1 } }
			)
			.toArray();
		let allowed: Set<string> | undefined;
		if (provisionedBy !== undefined && found.length) {
			allowed = new Set(
				(
					await this.groups
						.find(
							{
								_id: { $in: [...new Set(found.map((m) => m.groupId))] },
								provisionedBy
							},
							{ projection: { _id: 1 } }
						)
						.toArray()
				).map((g) => g._id)
			);
		}
		for (const m of found) {
			if (allowed && !allowed.has(m.groupId)) continue;
			result.get(m.userId)?.push(m.groupId);
		}
		for (const ids of result.values()) ids.sort();
		return result;
	}

	async change(
		groupId: string,
		change: BucketGroupChange
	): Promise<BucketGroup | null> {
		const current = await this.find(groupId);
		if (!current) return null;
		const merged = { ...current, ...change.attributes };
		const keys = bucketGroupKeysOf(merged);
		const set: Record<string, unknown> = {
			updatedAt: new Date(),
			displayNameKey: keys.displayNameKey
		};
		const unset: Record<string, ''> = {};
		for (const [field, value] of Object.entries({
			...change.attributes,
			externalIdKey: keys.externalIdKey
		})) {
			if (value === undefined) unset[field] = '';
			else set[field] = value;
		}
		try {
			return await this.atomically(async (session) => {
				const updated = await this.groups.findOneAndUpdate(
					{ _id: groupId },
					Object.keys(unset).length
						? { $set: set, $unset: unset }
						: { $set: set },
					{ returnDocument: 'after', session }
				);
				if (!updated) return null;
				await this.addMembers(current, change.add ?? [], session);
				await this.removeMembers(groupId, change.remove ?? [], session);
				return this.groupOf(updated);
			});
		} catch (error) {
			const taken = takenFrom(error, merged);
			if (taken) throw taken;
			throw error;
		}
	}

	async removeUser(bucketId: string, userId: string): Promise<void> {
		await this.members.deleteMany({ bucketId, userId });
	}

	async destroy(id: string): Promise<void> {
		await this.members.deleteMany({ groupId: id });
		await this.groups.deleteOne({ _id: id });
	}

	async destroyByBucket(bucketId: string): Promise<void> {
		await this.members.deleteMany({ bucketId });
		await this.groups.deleteMany({ bucketId });
	}
}
