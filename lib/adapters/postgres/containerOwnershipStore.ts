import { sql, type Tx } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { member } from '../../helpers/_/object.js';
import type {
	ContainerMoveResult,
	ContainerOwnershipStoreInstance
} from '../types.js';

/*
 * Moves a container between administrator groups in one transaction. The bucket row is locked first, so
 * a second move of the same bucket waits and then finds it no longer in a group it may move from.
 */
export class ContainerOwnershipStore implements ContainerOwnershipStoreInstance {
	private bucketArea: string = STORE_AREAS.userBuckets;
	private projectArea: string = STORE_AREAS.projects;

	async moveBucket(
		bucketId: string,
		from: string,
		to: string
	): Promise<ContainerMoveResult> {
		const handle = sql();
		return handle.begin(async (tx: Tx): Promise<ContainerMoveResult> => {
			const locked = await tx`
				SELECT doc->>'ownerGroupId' AS owner FROM ${tx(this.bucketArea)}
				WHERE id = ${bucketId}
				FOR UPDATE
			`;
			const owner = member(locked[0], 'owner');
			if (owner !== from && owner !== to) return { status: 'conflict' };

			const strays = await tx`
				SELECT 1 FROM ${tx(this.projectArea)}
				WHERE doc->>'bucketId' = ${bucketId}
					AND doc->>'ownerGroupId' <> ${from}
					AND doc->>'ownerGroupId' <> ${to}
				LIMIT 1
			`;
			if (strays.length > 0) return { status: 'conflict' };

			const patch = { ownerGroupId: to, updatedAt: new Date() };
			await tx`
				UPDATE ${tx(this.bucketArea)} SET doc = doc || ${patch}
				WHERE id = ${bucketId}
			`;
			const moved = await tx`
				UPDATE ${tx(this.projectArea)} SET doc = doc || ${patch}
				WHERE doc->>'bucketId' = ${bucketId} AND doc->>'ownerGroupId' = ${from}
				RETURNING id
			`;
			const projectIds = moved
				.map((row: unknown) => member(row, 'id'))
				.filter((id: unknown): id is string => typeof id === 'string');
			return { status: 'moved', projectIds };
		});
	}

	async moveProject(
		projectId: string,
		from: string,
		to: string
	): Promise<ContainerMoveResult> {
		const handle = sql();
		const patch = { ownerGroupId: to, updatedAt: new Date() };
		const rows = await handle`
			UPDATE ${handle(this.projectArea)} SET doc = doc || ${patch}
			WHERE id = ${projectId}
				AND doc->>'ownerGroupId' = ${from}
				AND doc->>'bucketId' IS NULL
			RETURNING id
		`;
		return rows.length === 0
			? { status: 'conflict' }
			: { status: 'moved', projectIds: [projectId] };
	}
}
