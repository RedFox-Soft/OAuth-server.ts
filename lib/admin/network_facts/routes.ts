import { Elysia } from 'elysia';

import { parseAddress } from '../../behind_proxy/net.js';
import { NETWORK_FACTS_TARGET_ID } from '../../consts/admin_audit_routes.js';
import { factsAt, networkFactsStatus } from '../../network_facts/state.js';
import { now } from '../../telemetry/clock.js';
import { recordAdminAudit } from '../audit/record.js';
import {
	assertAuth,
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../auth/rbac.js';
import {
	NetworkFactsLookupBody,
	NetworkFactsLookupResponse
} from './schema.js';

/*
 * What this server's copy of FoxTrust's snapshot says about one address (specs/129 FR-027), for "Check access": the
 * console decides in the browser and cannot hold the snapshot, so it asks here and hands the facts to the same pure
 * function the proxy check uses. Any administrator may ask: the answer is FoxTrust's public data. The address is only
 * compared, never sent anywhere, written to a log line or kept in the audit record.
 */
export const networkFactsRoutes = new Elysia({ name: 'admin-network-facts' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.post(
		'/admin/api/network-facts/lookup',
		async ({ admin, body }) => {
			const ctx = assertAuth(admin);
			const address = parseAddress(body.address.trim());
			if (!address) {
				throw new AdminError(400, 'Enter an IP address, such as 203.0.113.7.', {
					field: 'address',
					code: 'invalid_address'
				});
			}
			await recordAdminAudit(
				ctx,
				'networkfacts.lookup',
				NETWORK_FACTS_TARGET_ID,
				{
					attributes: []
				}
			);
			const atMs = now().getTime();
			const status = networkFactsStatus(atMs);
			const facts = factsAt(address, atMs);
			return {
				facts: facts.known
					? {
							known: true as const,
							categories: [...facts.categories],
							country: facts.country
						}
					: { known: false as const },
				state: status.state,
				fullVersion: status.held?.fullVersion ?? null,
				deltaVersion: status.held?.deltaVersion ?? null,
				builtAt: status.held?.builtAt ?? null,
				ageSeconds: status.held?.ageSeconds ?? null
			};
		},
		{
			body: NetworkFactsLookupBody,
			response: { 200: NetworkFactsLookupResponse }
		}
	);
