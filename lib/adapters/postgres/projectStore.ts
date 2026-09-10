import { sql } from './db.js';
import { docOf } from './json.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { reviveDates } from './dates.js';
import type { Project, ProjectStoreInstance } from '../types.js';
import nanoid from '../../helpers/nanoid.js';

const DATE_FIELDS = ['createdAt', 'updatedAt'] as const;

/*
 * Documents written before corsOrigins existed carry no such key, and there is no backfill: the field
 * is defaulted on read so every consumer sees the declared `string[]` rather than `undefined`.
 *
 * Kept on this backend even though no PostgreSQL deployment can hold such a document — there are no
 * PostgreSQL deployments older than the field. Dropping it would make the two stores answer
 * differently for the same input, which is a divergence with nothing to gain, and it would be the
 * first thing to go wrong if a record were ever moved between them.
 */
function withDefaults(project: Project | null): Project | null {
	if (!project) return null;
	return { ...project, corsOrigins: project.corsOrigins ?? [] };
}

export class ProjectStore implements ProjectStoreInstance {
	private area: string = STORE_AREAS.projects;

	async create(data: {
		_id?: string;
		name: string;
		slug: string;
		type?: 'admin' | 'regular';
		ownerGroupId: string;
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
			ownerGroupId: data.ownerGroupId,
			bucketId: data.bucketId ?? null,
			clientIds: data.clientIds ?? [],
			corsOrigins: data.corsOrigins ?? [],
			createdAt: now,
			updatedAt: now
		};

		const handle = sql();
		await handle`
			INSERT INTO ${handle(this.area)} (id, doc, expires_at)
			VALUES (${project._id}, ${project}, NULL)
		`;

		return project;
	}

	async find(id: string): Promise<Project | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE id = ${id}
		`;
		return this.projectOf(rows[0]);
	}

	async findBySlug(slug: string): Promise<Project | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE doc->>'slug' = ${slug}
		`;
		return this.projectOf(rows[0]);
	}

	async list(): Promise<Project[]> {
		const handle = sql();
		const rows = await handle`SELECT doc FROM ${handle(this.area)}`;
		return this.projectsOf(rows);
	}

	async listByGroup(groupId: string): Promise<Project[]> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE doc->>'ownerGroupId' = ${groupId}
		`;
		return this.projectsOf(rows);
	}

	async update(
		id: string,
		patch: Partial<
			Pick<
				Project,
				'name' | 'ownerGroupId' | 'bucketId' | 'clientIds' | 'corsOrigins'
			>
		>
	): Promise<Project | null> {
		const handle = sql();
		const merged = { ...patch, updatedAt: new Date() };
		const rows = await handle`
			UPDATE ${handle(this.area)} SET doc = doc || ${merged}
			WHERE id = ${id}
			RETURNING doc
		`;
		return this.projectOf(rows[0]);
	}

	async destroy(id: string): Promise<void> {
		const handle = sql();
		await handle`DELETE FROM ${handle(this.area)} WHERE id = ${id}`;
	}

	async countByBucket(bucketId: string): Promise<number> {
		const handle = sql();
		const rows = await handle`
			SELECT count(*)::int AS held FROM ${handle(this.area)}
			WHERE doc->>'bucketId' = ${bucketId}
		`;
		return Number((rows[0] as { held?: number } | undefined)?.held ?? 0);
	}

	/*
	 * On the request path for every browser-origin call to a client-based endpoint.
	 *
	 * A containment query, not an equality one: `clientIds` is an array, and MongoDB's equality syntax
	 * against a multikey index hides that. Here it needs `@>` and the GIN index the inventory declares
	 * — and the failure mode of getting it wrong is silence, because a scalar comparison against a
	 * whole array matches nothing and every CORS check would simply find no project.
	 */
	async findByClientId(clientId: string): Promise<Project | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE doc->'clientIds' @> ${[clientId]}
			LIMIT 1
		`;
		return this.projectOf(rows[0]);
	}

	private projectOf(row: unknown): Project | null {
		const doc = docOf<Project>(row);
		return doc === undefined
			? null
			: withDefaults(reviveDates(doc, DATE_FIELDS));
	}

	private projectsOf(rows: unknown[]): Project[] {
		return rows
			.map((row) => this.projectOf(row))
			.filter((project): project is Project => project !== null);
	}
}
