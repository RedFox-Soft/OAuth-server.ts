import type { SQL } from 'bun';
import { sql } from './db.js';
import { docOf } from './json.js';
import { isUniqueViolation } from './sqlState.js';
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
	type BucketGroupQueryResult,
	type BucketGroupStoreInstance,
	type EndUserPage,
	type NewBucketGroup
} from '../types.js';

/* A store method runs either on the pool or inside a transaction; both are tagged-template handles. */
type Handle = SQL;

/*
 * Bucket groups and their membership records. Uniqueness is the unique indexes'; a change is one
 * transaction. Membership inserts use `ON CONFLICT (id) DO NOTHING` deliberately — unlike the other stores
 * here, a collision on the deterministic `groupId:userId` id means the membership exists, which is the
 * outcome asked for rather than a refusal.
 */
export class BucketGroupStore implements BucketGroupStoreInstance {
	private area: string = STORE_AREAS.bucketGroups;
	private memberArea: string = STORE_AREAS.bucketGroupMembers;

	private groupOf(row: unknown): BucketGroup | null {
		const doc = docOf(row);
		return doc === undefined ? null : documentOf(this.area, BucketGroup, doc);
	}

	private groupsOf(rows: unknown[]): BucketGroup[] {
		return rows
			.map((row) => this.groupOf(row))
			.filter((g): g is BucketGroup => g !== null);
	}

	private async addMembers(
		tx: Handle,
		group: Pick<BucketGroup, '_id' | 'bucketId'>,
		userIds: string[]
	): Promise<void> {
		if (userIds.length === 0) return;
		const createdAt = new Date();
		/*
		 * One statement for any number of members. The records travel as one jsonb object — the encoding this
		 * client gets right for a plain object (json.ts) — and are unpacked in SQL, rather than relying on how
		 * the client encodes an array.
		 */
		const batch = {
			items: userIds.map((userId) => ({
				_id: membershipIdOf(group._id, userId),
				groupId: group._id,
				userId,
				bucketId: group.bucketId,
				createdAt
			}))
		};
		await tx`
			INSERT INTO ${tx(this.memberArea)} (id, doc, expires_at)
			SELECT item->>'_id', item, NULL
			FROM jsonb_array_elements(${batch}::jsonb -> 'items') AS item
			ON CONFLICT (id) DO NOTHING
		`;
	}

	/* Which unique key a refused write collided on, read back rather than parsed from an index name. */
	private async takenBy(
		id: string,
		group: Pick<
			BucketGroup,
			'displayName' | 'displayNameKey' | 'externalId' | 'externalIdKey'
		>
	): Promise<UniqueValueTaken | null> {
		const handle = sql();
		const byName = await handle`
			SELECT 1 FROM ${handle(this.area)}
			WHERE doc->>'displayNameKey' = ${group.displayNameKey} AND id <> ${id} LIMIT 1
		`;
		if (byName.length)
			return new UniqueValueTaken('displayName', group.displayName);
		if (group.externalIdKey !== undefined) {
			const byExternal = await handle`
				SELECT 1 FROM ${handle(this.area)}
				WHERE doc->>'externalIdKey' = ${group.externalIdKey} AND id <> ${id} LIMIT 1
			`;
			if (byExternal.length) {
				return new UniqueValueTaken('externalId', group.externalId ?? '');
			}
		}
		return null;
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
		const doc = withoutUndefined(group);
		const handle = sql();
		try {
			await handle.begin(async (tx) => {
				await tx`
					INSERT INTO ${tx(this.area)} (id, doc, expires_at)
					VALUES (${group._id}, ${doc}, NULL)
				`;
				await this.addMembers(tx, group, memberIds);
			});
		} catch (error) {
			if (!isUniqueViolation(error)) throw error;
			throw (await this.takenBy(group._id, group)) ?? error;
		}
		return doc;
	}

	async find(id: string): Promise<BucketGroup | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE id = ${id}
		`;
		return this.groupOf(rows[0]);
	}

	async findMany(ids: string[]): Promise<BucketGroup[]> {
		if (ids.length === 0) return [];
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE id IN ${handle(ids.slice(0, MAX_END_USER_PAGE))}
		`;
		return this.groupsOf(rows);
	}

	async query(
		filter: BucketGroupFilter,
		page: EndUserPage
	): Promise<BucketGroupQueryResult> {
		const { offset, limit } = clampPage(page, MAX_END_USER_PAGE);
		const handle = sql();
		let where = handle`doc->>'bucketId' = ${filter.bucketId}`;
		if (filter.provisionedBy !== undefined) {
			where = handle`${where} AND doc->>'provisionedBy' = ${filter.provisionedBy}`;
		}
		if (filter.id !== undefined) {
			where = handle`${where} AND id = ${filter.id}`;
		}
		if (filter.displayName !== undefined) {
			where = handle`${where} AND doc->>'displayNameKey' = ${displayNameKeyOf(filter.bucketId, filter.displayName)}`;
		}
		if (filter.externalId !== undefined) {
			/* An external identifier means something only within a connection; without one nothing matches. */
			where =
				filter.provisionedBy === undefined
					? handle`${where} AND FALSE`
					: handle`${where} AND doc->>'externalIdKey' = ${externalIdKeyOf(filter.provisionedBy, filter.externalId)}`;
		}
		if (filter.member !== undefined) {
			where = handle`${where} AND id IN (
				SELECT doc->>'groupId' FROM ${handle(this.memberArea)}
				WHERE doc->>'bucketId' = ${filter.bucketId} AND doc->>'userId' = ${filter.member}
			)`;
		}
		const [rows, counted] = await Promise.all([
			limit === 0
				? Promise.resolve([])
				: handle`
					SELECT doc FROM ${handle(this.area)} WHERE ${where}
					ORDER BY id LIMIT ${limit} OFFSET ${offset}
				`,
			handle`SELECT count(*)::int AS total FROM ${handle(this.area)} WHERE ${where}`
		]);
		return {
			groups: this.groupsOf(rows),
			totalResults: Number(counted[0]?.total ?? 0)
		};
	}

	async memberIds(groupId: string, page?: EndUserPage): Promise<string[]> {
		const handle = sql();
		let rows: Array<{ user_id: string }>;
		if (page) {
			const { offset, limit } = clampPage(page, MAX_END_USER_PAGE);
			if (limit === 0) return [];
			rows = await handle`
				SELECT doc->>'userId' AS user_id FROM ${handle(this.memberArea)}
				WHERE doc->>'groupId' = ${groupId}
				ORDER BY doc->>'groupId', doc->>'userId' LIMIT ${limit} OFFSET ${offset}
			`;
		} else {
			rows = await handle`
				SELECT doc->>'userId' AS user_id FROM ${handle(this.memberArea)}
				WHERE doc->>'groupId' = ${groupId}
				ORDER BY doc->>'groupId', doc->>'userId'
			`;
		}
		return rows.map((row) => row.user_id);
	}

	async memberCount(groupId: string): Promise<number> {
		const handle = sql();
		const rows = await handle`
			SELECT count(*)::int AS total FROM ${handle(this.memberArea)}
			WHERE doc->>'groupId' = ${groupId}
		`;
		return Number(rows[0]?.total ?? 0);
	}

	async groupIdsOf(
		bucketId: string,
		userIds: string[],
		provisionedBy?: string
	): Promise<Map<string, string[]>> {
		const result = new Map<string, string[]>(userIds.map((id) => [id, []]));
		if (userIds.length === 0) return result;
		const handle = sql();
		const rows: Array<{ user_id: string; group_id: string }> =
			provisionedBy === undefined
				? await handle`
					SELECT doc->>'userId' AS user_id, doc->>'groupId' AS group_id
					FROM ${handle(this.memberArea)}
					WHERE doc->>'bucketId' = ${bucketId} AND doc->>'userId' IN ${handle(userIds)}
				`
				: await handle`
					SELECT m.doc->>'userId' AS user_id, m.doc->>'groupId' AS group_id
					FROM ${handle(this.memberArea)} m
					JOIN ${handle(this.area)} g ON g.id = m.doc->>'groupId'
					WHERE m.doc->>'bucketId' = ${bucketId} AND m.doc->>'userId' IN ${handle(userIds)}
						AND g.doc->>'provisionedBy' = ${provisionedBy}
				`;
		for (const row of rows) result.get(row.user_id)?.push(row.group_id);
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
		const remove: string[] = [];
		for (const [field, value] of Object.entries({
			...change.attributes,
			externalIdKey: keys.externalIdKey
		})) {
			if (value === undefined) remove.push(field);
			else set[field] = value;
		}
		const handle = sql();
		try {
			return await handle.begin(async (tx) => {
				const rows = await tx`
					UPDATE ${tx(this.area)}
					SET doc = (doc - ${tx.array(remove, 'text')}) || ${set}
					WHERE id = ${groupId}
					RETURNING doc
				`;
				const updated = this.groupOf(rows[0]);
				if (!updated) return null;
				await this.addMembers(tx, current, change.add ?? []);
				const removing = (change.remove ?? []).map((u) =>
					membershipIdOf(groupId, u)
				);
				if (removing.length) {
					await tx`DELETE FROM ${tx(this.memberArea)} WHERE id IN ${tx(removing)}`;
				}
				return updated;
			});
		} catch (error) {
			if (!isUniqueViolation(error)) throw error;
			throw (await this.takenBy(groupId, { ...merged, ...keys })) ?? error;
		}
	}

	async removeUser(bucketId: string, userId: string): Promise<void> {
		const handle = sql();
		await handle`
			DELETE FROM ${handle(this.memberArea)}
			WHERE doc->>'bucketId' = ${bucketId} AND doc->>'userId' = ${userId}
		`;
	}

	async destroy(id: string): Promise<void> {
		const handle = sql();
		await handle.begin(async (tx) => {
			await tx`DELETE FROM ${tx(this.memberArea)} WHERE doc->>'groupId' = ${id}`;
			await tx`DELETE FROM ${tx(this.area)} WHERE id = ${id}`;
		});
	}

	async destroyByBucket(bucketId: string): Promise<void> {
		const handle = sql();
		await handle.begin(async (tx) => {
			await tx`DELETE FROM ${tx(this.memberArea)} WHERE doc->>'bucketId' = ${bucketId}`;
			await tx`DELETE FROM ${tx(this.area)} WHERE doc->>'bucketId' = ${bucketId}`;
		});
	}
}

/* jsonb has no `undefined`; an absent optional member is left out rather than written as null. */
function withoutUndefined<T extends object>(record: T): T {
	const copy = { ...record };
	for (const [field, value] of Object.entries(copy)) {
		if (value === undefined) Reflect.deleteProperty(copy, field);
	}
	return copy;
}
