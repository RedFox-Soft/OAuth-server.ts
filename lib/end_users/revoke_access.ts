import { adapter } from '../adapters/index.js';
import { ApplicationConfig } from '../configs/application.js';
import { areaNamed } from '../consts/storage_inventory.js';
import { sweepAccountOwned, type CascadeResult } from '../helpers/cascade.js';
import { Session } from '../models/session.js';
import { backchannelLogoutFor } from '../shared/destroy_session.js';

/*
 * Tells every relying party holding a session with this account that the session is over (OpenID Connect
 * Back-Channel Logout 1.0). Read before anything is swept: a logout token carries the session's `sid`, and the
 * session record is the only place that holds it.
 *
 * Delivery failures never stop the caller — `backchannelLogoutFor` reports each one as `backchannel.error` and
 * carries on, which is the behaviour a full sign-out already has. An account whose access must end does not
 * keep it because one relying party is unreachable.
 */
export async function notifyRelyingParties(accountId: string): Promise<void> {
	if (!ApplicationConfig['backchannelLogout.enabled']) return;

	const area = areaNamed('Session');
	const field = area.owners.account;
	if (field === null) {
		/* Unreachable while the inventory declares Session account-owned; a loud stop beats a silent skip. */
		throw new Error('the Session area declares no account owner to read by');
	}

	const stored = await adapter(area.name).findByOwner(field, accountId);
	await Promise.all(
		stored.map(async (record) => {
			/* Checked and expiry-judged as any session read is; an expired one has nobody left to tell. */
			const session = await Session.fromStored(record);
			if (!session) return;
			await backchannelLogoutFor(
				session,
				Object.keys(session.payload.authorizations ?? {})
			);
		})
	);
}

/*
 * Ends an account's access everywhere, at once: relying parties are told, then every record the inventory
 * declares the account owns — sessions, grants, tokens, codes, pending interactions — is destroyed. The caller
 * has already made the account unable to sign in, so a partial sweep leaves residue bounded by each area's
 * expiry and never a way back in.
 *
 * Introspection needs nothing further: it answers `active: false` once the grant behind a token is gone
 * (lib/actions/introspection.ts). A JWT access token validated locally by a resource server is the one thing
 * this cannot reach; it lives until its own expiry.
 */
export async function revokeAccountAccess(
	accountId: string
): Promise<CascadeResult> {
	await notifyRelyingParties(accountId);
	return sweepAccountOwned(accountId);
}
