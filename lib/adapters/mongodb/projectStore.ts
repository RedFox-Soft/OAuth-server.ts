import { db } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import type { Project, ProjectStoreInstance } from '../types.js';
import nanoid from '../../helpers/nanoid.js';

/*
 * Documents written before corsOrigins existed carry no such key, and there is no backfill: the field
 * is defaulted on read so every consumer sees the declared `string[]` rather than `undefined`. Cheaper
 * and safer than a migration for a field whose absence means "grants nothing" anyway.
 */
function withDefaults(project: Project | null): Project | null {
	if (!project) {
		return null;
	}
	return { ...project, corsOrigins: project.corsOrigins ?? [] };
}

export class ProjectStore implements ProjectStoreInstance {
	private collection = db.collection<Project>(STORE_AREAS.projects);

	async create(data: {
		_id?: string;
		name: string;
		slug: string;
		type?: 'admin' | 'regular';
		managedBy?: string[];
		bucketId?: string | null;
		clientIds?: string[];
		corsOrigins?: string[];
	}): Promise<Project> {
		const now = new Date();
		const project: Project = {
			_id: data._id ?? nanoid(),
			name: data.name,
			slug: data.slug,
			type: data.type ?? 'regular',
			managedBy: data.managedBy ?? [],
			bucketId: data.bucketId ?? null,
			clientIds: data.clientIds ?? [],
			corsOrigins: data.corsOrigins ?? [],
			createdAt: now,
			updatedAt: now
		};
		await this.collection.insertOne(project);
		return project;
	}

	async find(id: string): Promise<Project | null> {
		return withDefaults(await this.collection.findOne({ _id: id }));
	}

	async findBySlug(slug: string): Promise<Project | null> {
		return withDefaults(await this.collection.findOne({ slug }));
	}

	async list(): Promise<Project[]> {
		const all = await this.collection.find().toArray();
		return all.map((p) => withDefaults(p) as Project);
	}

	async listByManager(userId: string): Promise<Project[]> {
		const all = await this.collection.find({ managedBy: userId }).toArray();
		return all.map((p) => withDefaults(p) as Project);
	}

	async update(
		id: string,
		patch: Partial<
			Pick<
				Project,
				'name' | 'managedBy' | 'bucketId' | 'clientIds' | 'corsOrigins'
			>
		>
	): Promise<Project | null> {
		return withDefaults(
			await this.collection.findOneAndUpdate(
				{ _id: id },
				{ $set: { ...patch, updatedAt: new Date() } },
				{ returnDocument: 'after' }
			)
		);
	}

	async destroy(id: string): Promise<void> {
		await this.collection.deleteOne({ _id: id });
	}

	async countByBucket(bucketId: string): Promise<number> {
		return this.collection.countDocuments({ bucketId });
	}

	// On the request path for every browser-origin call to a client-based endpoint, hence the
	// `clientIds` index provisioned in database/mongodb.ts.
	async findByClientId(clientId: string): Promise<Project | null> {
		return withDefaults(await this.collection.findOne({ clientIds: clientId }));
	}
}
