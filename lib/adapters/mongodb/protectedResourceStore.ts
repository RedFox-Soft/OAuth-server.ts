import { db } from './db.js';
import { ABSENT_UNDEFINED } from './write_options.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import { UniqueValueTaken } from '../conflicts.js';
import { declarationId } from '../../resources/declaration_id.js';
import {
	ProtectedResource,
	type ProtectedResourcePatch,
	type ProtectedResourceStoreInstance
} from '../types.js';

function resourceOf(found: unknown): ProtectedResource | null {
	return found
		? documentOf(STORE_AREAS.protectedResources, ProtectedResource, found)
		: null;
}

function resourcesOf(found: unknown[]): ProtectedResource[] {
	return found.map((resource) =>
		documentOf(STORE_AREAS.protectedResources, ProtectedResource, resource)
	);
}

function isDuplicateKey(error: unknown): boolean {
	return (
		typeof error === 'object' &&
		error !== null &&
		'code' in error &&
		error.code === 11000
	);
}

/*
 * Declared protected resources, keyed by namespace and canonical identifier joined.
 *
 * `insertOne` is what enforces uniqueness, not a read-then-write check: the joined key is the `_id`, so
 * a duplicate is a primary-key violation the datastore refuses even under a concurrent write. The
 * route maps that failure to a conflict. Checking first and inserting after would be a race with a
 * window wide enough to matter, for no gain.
 */
export class ProtectedResourceStore implements ProtectedResourceStoreInstance {
	private collection = db.collection<ProtectedResource>(
		STORE_AREAS.protectedResources
	);

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
		try {
			await this.collection.insertOne(resource, ABSENT_UNDEFINED);
		} catch (error) {
			if (isDuplicateKey(error)) {
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
		return resourceOf(
			await this.collection.findOne({
				_id: declarationId(namespace, identifier)
			})
		);
	}

	async listByProject(projectId: string): Promise<ProtectedResource[]> {
		return resourcesOf(await this.collection.find({ projectId }).toArray());
	}

	async list(): Promise<ProtectedResource[]> {
		return resourcesOf(await this.collection.find().toArray());
	}

	async update(
		namespace: string,
		identifier: string,
		patch: ProtectedResourcePatch
	): Promise<ProtectedResource | null> {
		const result = await this.collection.findOneAndUpdate(
			{ _id: declarationId(namespace, identifier) },
			{ $set: { ...patch, updatedAt: new Date() } },
			{ returnDocument: 'after' }
		);
		return resourceOf(result);
	}

	async destroy(namespace: string, identifier: string): Promise<void> {
		await this.collection.deleteOne({
			_id: declarationId(namespace, identifier)
		});
	}

	async destroyByProject(projectId: string): Promise<number> {
		const result = await this.collection.deleteMany({ projectId });
		return result.deletedCount;
	}

	/*
	 * Every copy is written before any original is removed, so a failure part-way leaves the old
	 * namespace whole and only the new copies to undo. The primary key refuses a copy whose identifier
	 * a concurrent declaration took after the check below, which is the case the undo exists for.
	 */
	async moveProject(
		projectId: string,
		from: string,
		to: string
	): Promise<{ moved: number } | { conflicts: string[] }> {
		const moving = resourcesOf(
			await this.collection.find({ projectId, namespace: from }).toArray()
		);
		if (moving.length === 0) return { moved: 0 };
		const taken = resourcesOf(
			await this.collection
				.find({
					_id: { $in: moving.map((r) => declarationId(to, r.identifier)) }
				})
				.toArray()
		).map((r) => r.identifier);
		if (taken.length > 0) return { conflicts: taken };

		const written: string[] = [];
		for (const resource of moving) {
			const copy = {
				...resource,
				_id: declarationId(to, resource.identifier),
				namespace: to,
				updatedAt: new Date()
			};
			try {
				await this.collection.insertOne(copy, ABSENT_UNDEFINED);
				written.push(copy._id);
			} catch (error) {
				await this.collection.deleteMany({ _id: { $in: written } });
				if (isDuplicateKey(error)) return { conflicts: [resource.identifier] };
				throw error;
			}
		}
		await this.collection.deleteMany({
			_id: { $in: moving.map((r) => r._id) }
		});
		return { moved: moving.length };
	}
}
