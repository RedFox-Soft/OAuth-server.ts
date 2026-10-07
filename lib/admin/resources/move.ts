import { getProtectedResourceStore } from '../../adapters/index.js';
import { ROOT_NAMESPACE } from '../../resources/namespace.js';
import { AdminError, type AdminContext } from '../auth/rbac.js';
import { ROOT_DECLARATION_REFUSAL } from './refusals.js';

/*
 * Carrying a project's declarations into the namespace of the bucket it now belongs to.
 *
 * A declaration's namespace is derived from its project's bucket, so a project that changes bucket
 * without its declarations moving would leave them in a namespace that no longer resolves them — the
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
			'the bucket this project would move to already declares a resource this project declares'
		);
	}
}

/* Checked before the audit write, so a refused move leaves no entry describing a change nobody made. */
export async function planMove(
	ctx: AdminContext,
	projectId: string,
	from: string,
	to: string
): Promise<MovePlan> {
	if (from === to) return { from, to, count: 0 };

	const store = getProtectedResourceStore();
	const moving = (await store.listByProject(projectId)).filter(
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
	projectId: string,
	plan: MovePlan
): Promise<void> {
	if (plan.count === 0) return;
	const result = await getProtectedResourceStore().moveProject(
		projectId,
		plan.from,
		plan.to
	);
	if ('conflicts' in result) throw new DeclarationsConflict(result.conflicts);
}
