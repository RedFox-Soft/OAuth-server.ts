import { sql } from './db.js';
import { docOf } from './json.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { reviveDates } from './dates.js';
import type { Group, GroupMember, GroupStoreInstance } from '../types.js';
import nanoid from '../../helpers/nanoid.js';

const DATE_FIELDS = ['createdAt', 'updatedAt'] as const;

/*
 * Membership lookups are containment queries, not equality.
 *
 * `members` is an array of objects, so "which groups is this user in" asks whether the array contains
 * an element with that `userId`. MongoDB answers it with a multikey index and equality syntax that
 * hides the difference; PostgreSQL needs `@>` against a GIN index over the array, which is why the
 * inventory now declares `multikey: 'members'` on that key.
 *
 * Getting this wrong would not fail. A scalar comparison against the whole array simply never matches,
 * so every administrator would resolve to zero memberships and every managed container would look like
 * somebody else's.
 */
function memberFilter(userId: string): { userId: string }[] {
	return [{ userId }];
}

export class GroupStore implements GroupStoreInstance {
	private area: string = STORE_AREAS.groups;

	async create(data: {
		_id?: string;
		name: string;
		kind?: Group['kind'];
		members?: GroupMember[];
	}): Promise<Group> {
		const now = new Date();
		const group: Group = {
			_id: data._id ?? nanoid(),
			name: data.name,
			kind: data.kind ?? 'regular',
			members: data.members ?? [],
			createdAt: now,
			updatedAt: now
		};

		const handle = sql();
		await handle`
			INSERT INTO ${handle(this.area)} (id, doc, expires_at)
			VALUES (${group._id}, ${group}, NULL)
		`;

		return group;
	}

	async find(id: string): Promise<Group | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE id = ${id}
		`;
		return this.groupOf(rows[0]);
	}

	async list(): Promise<Group[]> {
		const handle = sql();
		const rows = await handle`SELECT doc FROM ${handle(this.area)}`;
		return this.groupsOf(rows);
	}

	/*
	 * On the request path for every admin call — `contextFor` resolves the caller's memberships here —
	 * which is what makes the GIN index over `members` worth having rather than a nicety.
	 */
	async listByMember(userId: string): Promise<Group[]> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE doc->'members' @> ${memberFilter(userId)}
		`;
		return this.groupsOf(rows);
	}

	async findPersonalFor(userId: string): Promise<Group | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE doc->>'kind' = 'personal'
			  AND doc->'members' @> ${memberFilter(userId)}
			LIMIT 1
		`;
		return this.groupOf(rows[0]);
	}

	/*
	 * `||` merges at the top level, which is what `$set` on named fields does on the other backend —
	 * a nested merge would silently keep a member the caller meant to remove.
	 */
	async update(
		id: string,
		patch: Partial<Pick<Group, 'name' | 'members'>>
	): Promise<Group | null> {
		const handle = sql();
		const merged = { ...patch, updatedAt: new Date() };
		const rows = await handle`
			UPDATE ${handle(this.area)} SET doc = doc || ${merged}
			WHERE id = ${id}
			RETURNING doc
		`;
		return this.groupOf(rows[0]);
	}

	async destroy(id: string): Promise<void> {
		const handle = sql();
		await handle`DELETE FROM ${handle(this.area)} WHERE id = ${id}`;
	}

	private groupOf(row: unknown): Group | null {
		const doc = docOf<Group>(row);
		return doc === undefined ? null : reviveDates(doc, DATE_FIELDS);
	}

	private groupsOf(rows: unknown[]): Group[] {
		return rows
			.map((row) => this.groupOf(row))
			.filter((group): group is Group => group !== null);
	}
}
