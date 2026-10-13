import { getGroupStore, getProjectStore } from 'lib/adapters/index.ts';
import { writeLogo } from 'lib/models/client/logo.ts';

/* A logo as an administrator would have stored it — the stored record, never the client object. */
export async function giveLogo(clientId: string, image: string): Promise<void> {
	await writeLogo(clientId, image);
}

/*
 * Another tenant's project holding `clientIds`: an administrator of this server made those clients, but
 * not of the group that owns the default bucket every tenant signs in through.
 */
export async function tenantProject(clientIds: string[]): Promise<void> {
	const tenant = await getGroupStore().create({
		name: 'Tenant',
		kind: 'regular',
		members: [{ userId: 'tenant-owner', role: 'owner' }]
	});
	const project = await getProjectStore().create({
		ownerGroupId: tenant._id,
		name: 'Partner',
		slug: 'partner-project'
	});
	await getProjectStore().update(project._id, { clientIds });
}
