import { Elysia } from 'elysia';

import {
	assertAuth,
	assertSuperAdmin,
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../../auth/rbac.js';
import { ApplicationConfig } from '../../../configs/application.js';
import {
	callerAddressOf,
	isTrustedProxy,
	type CallerAddress
} from '../../../helpers/caller_address.js';
import { CallerAddressCheckResponse } from './schema.js';

const FORWARDED_HEADERS = [
	'x-forwarded-for',
	'x-real-ip',
	'fly-client-ip',
	'cf-connecting-ip',
	'forwarded'
] as const;

/*
 * What contradicts the choice, judged on the operator's own request — the only request the operator can
 * vouch for. Each is a deployment the choice does not describe:
 *   - "fly" chosen, and no Fly-Client-IP arrived: the server is not behind Fly's edge, and a caller
 *     behind some other private proxy could write that header itself;
 *   - another choice, and a Fly-Client-IP that differs from the attributed address: the server is on Fly,
 *     where the rightmost X-Forwarded-For entry is the app's own address and every caller would share it;
 *   - forwarded headers arrived on a connection the choice does not trust: a proxy is in front that the
 *     choice does not know, so every caller looks like that proxy.
 */
function warningFor(request: Request, caller: CallerAddress) {
	const fly = request.headers.get('fly-client-ip')?.trim();
	const source = ApplicationConfig['clientAddress.source'];
	if (source === 'fly' && !fly) return 'fly-header-missing' as const;
	if (source !== 'fly' && fly && fly !== caller.address) {
		return 'fly-header-present' as const;
	}
	const forwarded = FORWARDED_HEADERS.some((name) => request.headers.has(name));
	if (
		forwarded &&
		caller.connection !== null &&
		!isTrustedProxy(caller.connection)
	) {
		return 'forwarded-ignored' as const;
	}
	return null;
}

/*
 * The caller address check (specs/115): read-only. The choice itself is the ordinary
 * `clientAddress.source` catalog entry, saved and audited through the generic settings route. Not
 * published to MCP: it describes the HTTP connection of the caller, and an agent's call is dispatched
 * inside the server with no connection at all.
 */
export const clientAddressSettingsRoutes = new Elysia({
	name: 'admin-settings-client-address'
})
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get(
		'/admin/api/settings/client-address',
		({ admin, request, server }) => {
			const ctx = assertAuth(admin);
			// How the instance is reached is an instance-wide fact, like the setting that decides it.
			assertSuperAdmin(ctx);
			const caller = callerAddressOf(request, server);
			return {
				source: ApplicationConfig['clientAddress.source'],
				attributed: { address: caller.address, from: caller.from },
				connection: caller.connection,
				forwardedHeaders: FORWARDED_HEADERS.filter((name) =>
					request.headers.has(name)
				),
				warning: warningFor(request, caller)
			};
		},
		{ response: { 200: CallerAddressCheckResponse } }
	);
