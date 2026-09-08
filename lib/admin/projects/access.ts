import { getProjectStore } from '../../adapters/index.js';
import type { Project } from '../../adapters/types.js';
import {
	AdminError,
	assertProjectAccess,
	type AdminContext
} from '../auth/rbac.js';

/*
 * Loads a project the caller is allowed to see, refusing identically whether it is missing or simply
 * theirs to not reach.
 *
 * The two used to differ — 404 for a project that does not exist, 403 for one owned by another group —
 * which handed an outsider an existence oracle: walk ids, and the status tells you which are real.
 * Harmless while a project id was only ever handed out by an operator; not harmless once any
 * administrator can create projects and every id belongs to somebody else's tenant.
 *
 * A super administrator still gets 404, because their authority is instance-wide: there is no tenant
 * they could be probing, and collapsing the two would only make a real "wrong id" harder to diagnose.
 *
 * Extracted from `projects/routes.ts` when a second route group came to need it. Deliberately shared
 * rather than copied: this is a security-relevant refusal, and two copies of it would be two chances
 * for one to drift back into an oracle.
 */
export async function loadProject(
	admin: AdminContext,
	id: string
): Promise<Project> {
	const project = await getProjectStore().find(id);
	if (!project) {
		if (admin.roles.includes('super_admin')) {
			throw new AdminError(404, 'project not found');
		}
		throw new AdminError(403, 'no access to this project');
	}
	assertProjectAccess(admin, project);
	return project;
}
