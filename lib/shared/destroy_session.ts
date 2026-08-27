import { ApplicationConfig } from 'lib/configs/application.js';
import { Client } from 'lib/models/client.js';
import { Session } from 'lib/models/session.js';
import { eventBus } from '../event_bus.js';
import revoke from '../helpers/revoke.ts';

/*
 * Notifies the given clients that a session has ended, for those that asked to be told.
 *
 * `accountId` and `sid` must be read off the session while it still exists, which is the whole
 * reason this runs before the record is destroyed rather than after.
 */
export async function backchannelLogoutFor(
	session: Session,
	clientIds: string[],
	ctx?: { oidc: unknown }
): Promise<void> {
	const back = [];

	for (const clientId of clientIds) {
		const client = await Client.tryFind(clientId);
		if (client) {
			const sid = session.sidFor(client.clientId);
			if (client.backchannelLogoutUri) {
				const { accountId } = session.payload;
				back.push(
					client.backchannelLogout(accountId, sid).then(
						() => {
							eventBus.emit('backchannel.success', ctx, client, accountId, sid);
						},
						(err) => {
							eventBus.emit(
								'backchannel.error',
								ctx,
								err,
								client,
								accountId,
								sid
							);
						}
					)
				);
			}
		}
	}

	await Promise.all(back);
}

/*
 * Ends a provider session completely: every relying party that asked for backchannel logout is
 * told, the grants that do not survive a sign-out are revoked, and the session record is destroyed.
 *
 * Extracted from the end-session `logout=true` branch so the admin console can end the provider
 * session server-side without re-implementing it — the console is a relying party on its own issuer
 * ([[admin-console-signin]]), and destroying only its own BFF session left the provider session
 * alive, which silently re-authenticated the operator on the very next request. A second copy of
 * this teardown would have drifted on the first change, and the parts that are easy to leave out —
 * the backchannel fan-out, and reading the session's fields before it is gone — are exactly the
 * parts nothing would report missing.
 *
 * `ctx` only reaches the event bus; the admin path has no OIDCContext to offer.
 */
export async function destroyProviderSession(
	session: Session,
	ctx?: { oidc: unknown }
): Promise<void> {
	if (ApplicationConfig['backchannelLogout.enabled']) {
		await backchannelLogoutFor(
			session,
			Object.keys(session.payload.authorizations || {}),
			ctx
		);
	}

	if (session.payload.authorizations) {
		await Promise.all(
			Object.entries(session.payload.authorizations).map(
				async ([clientId, { grantId }]) => {
					// Drop the grants without offline_access
					// Note: tokens that don't get dropped due to offline_access having being added
					// later will still not work, as such they will be orphaned until their TTL hits
					if (grantId && !session.authorizationFor(clientId).persistsLogout) {
						await revoke(grantId);
					}
				}
			)
		);
	}

	await session.destroy();
}
