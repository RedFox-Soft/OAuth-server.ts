import { sql } from './db.js';
import { docOf } from './json.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { reviveDates } from './dates.js';
import type {
	ProtectedResource,
	ProtectedResourceStoreInstance
} from '../types.js';

const DATE_FIELDS = ['createdAt', 'updatedAt'] as const;

/*
 * Declared protected resources, keyed by the canonical resource identifier.
 *
 * A plain INSERT is what enforces uniqueness, not a read-then-write check: the identifier is the
 * primary key, so a duplicate is a constraint violation the datastore refuses even under a concurrent
 * write, and the route maps that failure to a conflict. Checking first and inserting after would be a
 * race with a window wide enough to matter, for no gain — the same reasoning, and the same absence of
 * `ON CONFLICT`, as the MongoDB store's bare `insertOne`.
 */
export class ProtectedResourceStore implements ProtectedResourceStoreInstance {
	private area: string = STORE_AREAS.protectedResources;

	async create(data: {
		_id: string;
		projectId: string;
		name: string;
		scopes: string[];
		tokenFormat?: 'jwt' | 'opaque';
		accessTokenTTL?: number;
		trailingSlashSignificant?: boolean;
	}): Promise<ProtectedResource> {
		const now = new Date();
		const resource: ProtectedResource = {
			_id: data._id,
			projectId: data.projectId,
			name: data.name,
			scopes: [...data.scopes],
			tokenFormat: data.tokenFormat ?? 'jwt',
			accessTokenTTL: data.accessTokenTTL ?? 900,
			trailingSlashSignificant: data.trailingSlashSignificant ?? false,
			createdAt: now,
			updatedAt: now
		};

		const handle = sql();
		await handle`
			INSERT INTO ${handle(this.area)} (id, doc, expires_at)
			VALUES (${resource._id}, ${resource}, NULL)
		`;

		return resource;
	}

	async find(id: string): Promise<ProtectedResource | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE id = ${id}
		`;
		return this.resourceOf(rows[0]);
	}

	async listByProject(projectId: string): Promise<ProtectedResource[]> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE doc->>'projectId' = ${projectId}
		`;
		return this.resourcesOf(rows);
	}

	async list(): Promise<ProtectedResource[]> {
		const handle = sql();
		const rows = await handle`SELECT doc FROM ${handle(this.area)}`;
		return this.resourcesOf(rows);
	}

	async update(
		id: string,
		patch: Partial<
			Pick<
				ProtectedResource,
				'name' | 'scopes' | 'tokenFormat' | 'accessTokenTTL'
			>
		>
	): Promise<ProtectedResource | null> {
		const handle = sql();
		const merged = { ...patch, updatedAt: new Date() };
		const rows = await handle`
			UPDATE ${handle(this.area)} SET doc = doc || ${merged}
			WHERE id = ${id}
			RETURNING doc
		`;
		return this.resourceOf(rows[0]);
	}

	async destroy(id: string): Promise<void> {
		const handle = sql();
		await handle`DELETE FROM ${handle(this.area)} WHERE id = ${id}`;
	}

	async destroyByProject(projectId: string): Promise<number> {
		const handle = sql();
		const rows = await handle`
			DELETE FROM ${handle(this.area)} WHERE doc->>'projectId' = ${projectId}
			RETURNING id
		`;
		return rows.length;
	}

	private resourceOf(row: unknown): ProtectedResource | null {
		const doc = docOf<ProtectedResource>(row);
		return doc === undefined ? null : reviveDates(doc, DATE_FIELDS);
	}

	private resourcesOf(rows: unknown[]): ProtectedResource[] {
		return rows
			.map((row) => this.resourceOf(row))
			.filter((resource): resource is ProtectedResource => resource !== null);
	}
}
