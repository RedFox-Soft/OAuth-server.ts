import type { Project, ProjectStoreInstance } from '../types.js';
import nanoid from '../../helpers/nanoid.js';

export class ProjectStore implements ProjectStoreInstance {
	private projects = new Map<string, Project>();

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
		this.projects.set(project._id, project);
		return project;
	}

	async find(id: string): Promise<Project | null> {
		return this.projects.get(id) ?? null;
	}

	async findBySlug(slug: string): Promise<Project | null> {
		for (const p of this.projects.values()) {
			if (p.slug === slug) return p;
		}
		return null;
	}

	async list(): Promise<Project[]> {
		return [...this.projects.values()];
	}

	async listByManager(userId: string): Promise<Project[]> {
		return [...this.projects.values()].filter((p) =>
			p.managedBy.includes(userId)
		);
	}

	async update(
		id: string,
		patch: Partial<Pick<Project, 'name' | 'managedBy' | 'bucketId' | 'clientIds'>>
	): Promise<Project | null> {
		const p = this.projects.get(id);
		if (!p) return null;
		Object.assign(p, patch, { updatedAt: new Date() });
		return p;
	}

	async destroy(id: string): Promise<void> {
		this.projects.delete(id);
	}

	async countByBucket(bucketId: string): Promise<number> {
		return [...this.projects.values()].filter((p) => p.bucketId === bucketId)
			.length;
	}
}
