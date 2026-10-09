import { sql, type Tx } from './db.js';
import { docOf } from './json.js';
import { isUniqueViolation } from './sqlState.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import { UniqueValueTaken } from '../conflicts.js';
import { declarationId } from '../../resources/declaration_id.js';
import {
	ProtectedResource,
	type ProtectedResourcePatch,
	type ProtectedResourceStoreInstance
} from '../types.js';

/*
 * Declared protected resources, keyed by namespace and canonical identifier joined.
 *
 * A plain INSERT is what enforces uniqueness, not a read-then-write check: the joined key is the
 * primary key, so a duplicate is a constraint violation the datastore refuses even under a concurrent
 * write, and the route maps that failure to a conflict. Checking first and inserting after would be a
 * race with a window wide enough to matter, for no gain — the same reasoning, and the same absence of
 * `ON CONFLICT`, as the MongoDB store's bare `insertOne`.
 */
export class ProtectedResourceStore implements ProtectedResourceStoreInstance {
	private area: string = STORE_AREAS.protectedResources;

	async create(data: {
		namespace: string;
		identifier: string;
		projectId: string;
		name: string;
		scopes: string[];
		tokenFormat?: 'jwt' | 'opaque';
		accessTokenTTL?: number;
		trailingSlashSignificant?: boolean;
	}): Promise<ProtectedResource> {
		const now = new Date();
		const resource: ProtectedResource = {
			_id: declarationId(data.namespace, data.identifier),
			namespace: data.namespace,
			identifier: data.identifier,
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
		try {
			await handle`
				INSERT INTO ${handle(this.area)} (id, doc, expires_at)
				VALUES (${resource._id}, ${resource}, NULL)
			`;
		} catch (error) {
			if (isUniqueViolation(error)) {
				throw new UniqueValueTaken('resource', data.identifier);
			}
			throw error;
		}

		return resource;
	}

	async find(
		namespace: string,
		identifier: string
	): Promise<ProtectedResource | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE id = ${declarationId(namespace, identifier)}
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
		namespace: string,
		identifier: string,
		patch: ProtectedResourcePatch
	): Promise<ProtectedResource | null> {
		const handle = sql();
		const merged = { ...patch, updatedAt: new Date() };
		const rows = await handle`
			UPDATE ${handle(this.area)} SET doc = doc || ${merged}
			WHERE id = ${declarationId(namespace, identifier)}
			RETURNING doc
		`;
		return this.resourceOf(rows[0]);
	}

	async destroy(namespace: string, identifier: string): Promise<void> {
		const handle = sql();
		await handle`
			DELETE FROM ${handle(this.area)}
			WHERE id = ${declarationId(namespace, identifier)}
		`;
	}

	async destroyByProject(projectId: string): Promise<number> {
		const handle = sql();
		const rows = await handle`
			DELETE FROM ${handle(this.area)} WHERE doc->>'projectId' = ${projectId}
			RETURNING id
		`;
		return rows.length;
	}

	/*
	 * One transaction here, which the adapter contract does not promise but this backend gives for
	 * free: a copy refused by the primary key — an identifier a concurrent declaration took after the
	 * check — rolls every earlier copy back with it, and the originals are never touched until all the
	 * copies are in.
	 */
	async moveProject(
		projectId: string,
		from: string,
		to: string
	): Promise<{ moved: number } | { conflicts: string[] }> {
		const moving = await this.listByProject(projectId).then((all) =>
			all.filter((r) => r.namespace === from)
		);
		if (moving.length === 0) return { moved: 0 };
		const targets = moving.map((r) => declarationId(to, r.identifier));
		const handle = sql();
		const taken = this.resourcesOf(
			await handle`
				SELECT doc FROM ${handle(this.area)} WHERE id IN ${handle(targets)}
			`
		).map((r) => r.identifier);
		if (taken.length > 0) return { conflicts: taken };

		try {
			await handle.begin(async (tx: Tx) => {
				for (const resource of moving) {
					const copy = {
						...resource,
						_id: declarationId(to, resource.identifier),
						namespace: to,
						updatedAt: new Date()
					};
					await tx`
						INSERT INTO ${tx(this.area)} (id, doc, expires_at)
						VALUES (${copy._id}, ${copy}, NULL)
					`;
				}
				await tx`
					DELETE FROM ${tx(this.area)} WHERE id IN ${tx(moving.map((r) => r._id))}
				`;
			});
		} catch (error) {
			if (isUniqueViolation(error)) {
				return { conflicts: moving.map((r) => r.identifier) };
			}
			throw error;
		}
		return { moved: moving.length };
	}

	private resourceOf(row: unknown): ProtectedResource | null {
		const doc = docOf(row);
		return doc === undefined
			? null
			: documentOf(this.area, ProtectedResource, doc);
	}

	private resourcesOf(rows: unknown[]): ProtectedResource[] {
		return rows
			.map((row) => this.resourceOf(row))
			.filter((resource): resource is ProtectedResource => resource !== null);
	}
}
