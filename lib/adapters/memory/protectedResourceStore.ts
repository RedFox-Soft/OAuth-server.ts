import type {
	ProtectedResource,
	ProtectedResourcePatch,
	ProtectedResourceStoreInstance
} from '../types.js';
import { UniqueValueTaken } from '../conflicts.js';
import { declarationId } from '../../resources/declaration_id.js';

/*
 * In-memory declared protected resources.
 *
 * `create` refuses a duplicate within a namespace rather than overwriting, so the uniqueness the
 * datastores' primary key gives is observable in the default test run too. It is not the same
 * guarantee — this cannot survive a concurrent write, which is what database/verify_postgres.ts is for —
 * but a store that silently replaced a declaration would make the *behavioural* rule untestable as well.
 */
export class ProtectedResourceStore implements ProtectedResourceStoreInstance {
	private resources = new Map<string, ProtectedResource>();

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
		const _id = declarationId(data.namespace, data.identifier);
		if (this.resources.has(_id)) {
			throw new UniqueValueTaken('resource', data.identifier);
		}

		const now = new Date();
		const resource: ProtectedResource = {
			_id,
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
		this.resources.set(_id, resource);
		return { ...resource, scopes: [...resource.scopes] };
	}

	async find(
		namespace: string,
		identifier: string
	): Promise<ProtectedResource | null> {
		return this.resources.get(declarationId(namespace, identifier)) ?? null;
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
		namespace: string,
		identifier: string,
		patch: ProtectedResourcePatch
	): Promise<ProtectedResource | null> {
		const resource = this.resources.get(declarationId(namespace, identifier));
		if (!resource) return null;
		Object.assign(resource, patch, { updatedAt: new Date() });
		return resource;
	}

	async destroy(namespace: string, identifier: string): Promise<void> {
		this.resources.delete(declarationId(namespace, identifier));
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

	async moveProject(
		projectId: string,
		from: string,
		to: string
	): Promise<{ moved: number } | { conflicts: string[] }> {
		const moving = [...this.resources.values()].filter(
			(r) => r.projectId === projectId && r.namespace === from
		);
		const conflicts = moving
			.filter((r) => this.resources.has(declarationId(to, r.identifier)))
			.map((r) => r.identifier);
		if (conflicts.length > 0) return { conflicts };

		for (const resource of moving) {
			this.resources.delete(resource._id);
			const _id = declarationId(to, resource.identifier);
			this.resources.set(_id, {
				...resource,
				_id,
				namespace: to,
				updatedAt: new Date()
			});
		}
		return { moved: moving.length };
	}
}
