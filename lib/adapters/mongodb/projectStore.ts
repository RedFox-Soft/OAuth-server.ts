import { db } from './db.js';
import type { Project, ProjectStoreInstance } from '../types.js';
import nanoid from '../../helpers/nanoid.js';

export class ProjectStore implements ProjectStoreInstance {
	private collection = db.collection<Project>('projects');

	async create(data: {
		_id?: string;
		name: string;
		slug: string;
		type?: 'admin' | 'regular';
		managedBy?: string[];
		bucketId?: string | null;
		clientIds?: string[];
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
			createdAt: now,
			updatedAt: now
		};
		await this.collection.insertOne(project);
		return project;
	}

	async find(id: string): Promise<Project | null> {
		return this.collection.findOne({ _id: id });
	}

	async findBySlug(slug: string): Promise<Project | null> {
		return this.collection.findOne({ slug });
	}

	async list(): Promise<Project[]> {
		return this.collection.find().toArray();
	}

	async listByManager(userId: string): Promise<Project[]> {
		return this.collection.find({ managedBy: userId }).toArray();
	}

	async update(
		id: string,
		patch: Partial<Pick<Project, 'name' | 'managedBy' | 'bucketId' | 'clientIds'>>
	): Promise<Project | null> {
		return this.collection.findOneAndUpdate(
			{ _id: id },
			{ $set: { ...patch, updatedAt: new Date() } },
			{ returnDocument: 'after' }
		);
	}

	async destroy(id: string): Promise<void> {
		await this.collection.deleteOne({ _id: id });
	}

	async countByBucket(bucketId: string): Promise<number> {
		return this.collection.countDocuments({ bucketId });
	}
}
