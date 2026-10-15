import { getProtectedResourceStore } from '../../adapters/index.js';
import type { ProtectedResource } from '../../adapters/types.js';
import { ROOT_NAMESPACE } from '../../resources/namespace.js';
import { AdminError, type AdminContext } from '../auth/rbac.js';
import { ROOT_DECLARATION_REFUSAL } from './refusals.js';

/*
 * Carrying a bucket's declarations into the namespace its new address gives it.
 *
 * A declaration's namespace is derived from its bucket's address, so a bucket that gains an address of its
 * own without its declarations moving would leave them in a namespace that no longer resolves them — the
 * resource would stop being issued tokens at the new address and keep answering at the old one. Moving
 * them is therefore part of the change, and refusing the change is the only answer when they cannot
 * move: the target namespace already declares one of the identifiers, or the target is the shared root,
 * which only a super administrator writes.
 */
export interface MovePlan {
	readonly from: string;
	readonly to: string;
	readonly count: number;
}

export class DeclarationsConflict extends AdminError {
	constructor(readonly conflicts: string[]) {
		super(
			409,
			'the namespace this bucket would move to already declares a resource this bucket declares'
		);
	}
}

/*
 * What `planMove` would decide, stated instead of thrown, for a preview shown before anyone consents
 * (specs/085): the declarations that would move, the identifiers already taken where they would go, and
 * whether the destination is the shared root this caller may not write. `planMove` stays the check at
 * confirm time, because what was true when the preview was read may not be true now.
 */
export interface MovePreview {
	readonly moving: readonly ProtectedResource[];
	readonly conflicts: readonly string[];
	readonly rootRefused: boolean;
}

export async function previewMove(
	ctx: AdminContext,
	bucketId: string,
	from: string,
	to: string
): Promise<MovePreview> {
	if (from === to) return { moving: [], conflicts: [], rootRefused: false };

	const store = getProtectedResourceStore();
	const moving = (await store.listByBucket(bucketId)).filter(
		(r) => r.namespace === from
	);
	const conflicts: string[] = [];
	for (const resource of moving) {
		if (await store.find(to, resource.identifier)) {
			conflicts.push(resource.identifier);
		}
	}
	return {
		moving,
		conflicts,
		rootRefused: moving.length > 0 && to === ROOT_NAMESPACE && !ctx.superAdmin
	};
}

/* Checked before the audit write, so a refused move leaves no entry describing a change nobody made. */
export async function planMove(
	ctx: AdminContext,
	bucketId: string,
	from: string,
	to: string
): Promise<MovePlan> {
	if (from === to) return { from, to, count: 0 };

	const store = getProtectedResourceStore();
	const moving = (await store.listByBucket(bucketId)).filter(
		(r) => r.namespace === from
	);
	if (moving.length === 0) return { from, to, count: 0 };

	if (to === ROOT_NAMESPACE && !ctx.superAdmin) {
		throw new AdminError(403, ROOT_DECLARATION_REFUSAL);
	}

	const conflicts: string[] = [];
	for (const resource of moving) {
		if (await store.find(to, resource.identifier)) {
			conflicts.push(resource.identifier);
		}
	}
	if (conflicts.length > 0) throw new DeclarationsConflict(conflicts);

	return { from, to, count: moving.length };
}

/* After the audit write. The store refuses a race the plan could not see, and undoes its own moves. */
export async function applyMove(
	bucketId: string,
	plan: MovePlan
): Promise<void> {
	if (plan.count === 0) return;
	const result = await getProtectedResourceStore().moveBucketNamespace(
		bucketId,
		plan.from,
		plan.to
	);
	if ('conflicts' in result) throw new DeclarationsConflict(result.conflicts);
}
