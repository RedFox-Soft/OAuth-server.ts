import { adminSessionStore } from '../../adapters/index.js';
import { AdminError } from '../auth/rbac.js';
import { revokeAccountAccess } from '../../end_users/revoke_access.js';

/*
 * Ends an administrator's access to the console without touching their account (specs/083): every console
 * session they hold, and every grant and token at the console's issuer — so an agent acting for them loses
 * its token too. They can sign in again at once, as themselves. Answers how many console sessions ended.
 *
 * Shared by the recovery routes and by an invitation that reclaims an account whose address was never proven
 * (lib/admin/groups/accept.ts), where whatever the earlier registrant obtained must not outlive the reclaim.
 */
export async function signOutAdministrator(userId: string): Promise<number> {
	const sessions = await adminSessionStore.destroyByUser(userId);
	const revoked = await revokeAccountAccess(userId);
	if (revoked.failedAreas.length > 0) {
		throw new AdminError(
			500,
			`the administrator was signed out of the console, but their access survives in: ${revoked.failedAreas.join(', ')}`,
			{ failedAreas: revoked.failedAreas }
		);
	}
	return sessions;
}
