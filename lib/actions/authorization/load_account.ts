import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import { findAccount } from '../../addon/account.js';

/*
 * Loads the End-User's account referenced by the session.
 */
export default async function loadAccount(oidc: OIDCContext) {
	const { accountId } = oidc.session.payload;

	if (accountId) {
		const account = await findAccount(oidc, accountId);
		// The DB-backed default resolver returns nothing for a deleted or
		// deactivated account; skip binding the entity so the interaction
		// pipeline treats the session as not-logged-in rather than binding null.
		if (account) {
			oidc.entity('Account', account);
		}
	}
}
