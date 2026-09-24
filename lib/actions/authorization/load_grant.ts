import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
import { Grant } from 'lib/models/grant.js';
import { loadExistingGrant } from '../../addon/index.js';

/*
 * Load or establish a new Grant object when the user is known.
 */
export default async function loadGrant(oidc: OIDCContext<PipelineParams>) {
	const account = oidc.entities.Account;
	if (account) {
		let grant = await loadExistingGrant(oidc);
		if (grant) {
			if (grant.payload.accountId !== account.accountId) {
				throw new Error('accountId mismatch');
			}
			if (grant.payload.clientId !== oidc.client.clientId) {
				throw new Error('clientId mismatch');
			}
			oidc.session.ensureClientContainer(oidc.client.clientId);
			oidc.session.grantIdFor(oidc.client.clientId, grant.id);
		} else {
			grant = new Grant({
				accountId: account.accountId,
				clientId: oidc.client.clientId
			});
		}
		oidc.entity('Grant', grant);
	}
}
