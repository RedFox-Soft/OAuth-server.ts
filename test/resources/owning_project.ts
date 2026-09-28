import { getProjectStore } from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';

/*
 * The project a client belongs to, for a declared resource to belong to as well. A client credentials
 * token for a declared resource goes only to a client of the declaring project, so a spec minting one
 * has to seed the project the way an administrator would.
 *
 * Reused rather than created per call: a client belongs to one project, the project store outlives a
 * spec file, and a second project holding the same client would make which one it belongs to depend
 * on the order the specs ran in.
 */
export async function projectOf(clientId: string): Promise<string> {
	const store = getProjectStore();
	const existing = await store.findByClientId(clientId);
	if (existing) return existing._id;

	const project = await store.create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: `Project of ${clientId}`,
		slug: `project-${Math.random()}`
	});
	await store.update(project._id, { clientIds: [clientId] });
	return project._id;
}
