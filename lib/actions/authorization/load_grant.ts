import { Grant } from 'lib/models/grant.js';
import { loadExistingGrant } from '../../addon/index.js';

/*
 * Load or establish a new Grant object when the user is known.
 */
export default async function loadGrant(oidc) {
	if (oidc.account) {
		let grant = await loadExistingGrant(oidc);
		if (grant) {
			if (grant.payload.accountId !== oidc.account.accountId) {
				throw new Error('accountId mismatch');
			}
			if (grant.payload.clientId !== oidc.client.clientId) {
				throw new Error('clientId mismatch');
			}
			oidc.session.ensureClientContainer(oidc.params.client_id);
			oidc.session.grantIdFor(oidc.params.client_id, grant.id);
		} else {
			grant = new Grant({
				accountId: oidc.account.accountId,
				clientId: oidc.client.clientId
			});
		}
		oidc.entity('Grant', grant);
	}
}
