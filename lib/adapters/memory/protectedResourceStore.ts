import type {
	ProtectedResource,
	ProtectedResourceStoreInstance
} from '../types.js';

/*
 * In-memory declared protected resources.
 *
 * `create` refuses a duplicate identifier rather than overwriting, so the uniqueness the Mongo
 * primary key gives is observable in the default test run too. It is not the same guarantee — this
 * cannot survive a concurrent write, and that gap is recorded in the feature's quickstart — but a
 * store that silently replaced a declaration would make the *behavioural* rule untestable as well.
 */
export class ProtectedResourceStore implements ProtectedResourceStoreInstance {
	private resources = new Map<string, ProtectedResource>();

	async create(data: {
		_id: string;
		projectId: string;
		name: string;
		scopes: string[];
		tokenFormat?: 'jwt' | 'opaque';
		accessTokenTTL?: number;
		trailingSlashSignificant?: boolean;
	}): Promise<ProtectedResource> {
		if (this.resources.has(data._id)) {
			throw new Error(`protected resource already declared: ${data._id}`);
		}

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
		this.resources.set(resource._id, resource);
		return resource;
	}

	async find(id: string): Promise<ProtectedResource | null> {
		return this.resources.get(id) ?? null;
	}

	async listByProject(projectId: string): Promise<ProtectedResource[]> {
		return [...this.resources.values()].filter(
			(r) => r.projectId === projectId
		);
	}

	async list(): Promise<ProtectedResource[]> {
		return [...this.resources.values()];
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
		const resource = this.resources.get(id);
		if (!resource) return null;
		Object.assign(resource, patch, { updatedAt: new Date() });
		return resource;
	}

	async destroy(id: string): Promise<void> {
		this.resources.delete(id);
	}

	/*
	 * Returns how many went, because the project-delete handler reports it. A cascade that said
	 * nothing would leave an operator unable to tell a project with no resources from one whose
	 * resources were removed under them.
	 */
	async destroyByProject(projectId: string): Promise<number> {
		let removed = 0;
		for (const [id, resource] of this.resources) {
			if (resource.projectId === projectId) {
				this.resources.delete(id);
				removed += 1;
			}
		}
		return removed;
	}
}
