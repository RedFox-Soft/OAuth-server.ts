import { db } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import type {
	ProtectedResource,
	ProtectedResourceStoreInstance
} from '../types.js';

/*
 * Declared protected resources, keyed by the canonical resource identifier.
 *
 * `insertOne` is what enforces uniqueness (FR-006), not a read-then-write check: the identifier is
 * the `_id`, so a duplicate is a primary-key violation the datastore refuses even under a concurrent
 * write. The route maps that failure to a conflict. Checking first and inserting after would be a
 * race with a window wide enough to matter, for no gain.
 */
export class ProtectedResourceStore implements ProtectedResourceStoreInstance {
	private collection = db.collection<ProtectedResource>(
		STORE_AREAS.protectedResources
	);

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
		await this.collection.insertOne(resource);
		return resource;
	}

	async find(id: string): Promise<ProtectedResource | null> {
		return this.collection.findOne({ _id: id });
	}

	async listByProject(projectId: string): Promise<ProtectedResource[]> {
		return this.collection.find({ projectId }).toArray();
	}

	async list(): Promise<ProtectedResource[]> {
		return this.collection.find().toArray();
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
		const result = await this.collection.findOneAndUpdate(
			{ _id: id },
			{ $set: { ...patch, updatedAt: new Date() } },
			{ returnDocument: 'after' }
		);
		return result ?? null;
	}

	async destroy(id: string): Promise<void> {
		await this.collection.deleteOne({ _id: id });
	}

	async destroyByProject(projectId: string): Promise<number> {
		const result = await this.collection.deleteMany({ projectId });
		return result.deletedCount;
	}
}
