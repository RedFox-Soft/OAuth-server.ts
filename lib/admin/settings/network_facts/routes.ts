import { Elysia } from 'elysia';

import { networkFactsStatus } from '../../../network_facts/state.js';
import { now } from '../../../telemetry/clock.js';
import {
	assertAuth,
	assertSuperAdmin,
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../../auth/rbac.js';
import { NetworkFactsStatusResponse } from './schema.js';

/*
 * The state of FoxTrust's network facts in the process that answers (specs/129). Super administrators only, like the
 * attacker list's card: the switch is instance-wide. Every administrator sees the short form beside their conditions.
 */
export const networkFactsSettingsRoutes = new Elysia({
	name: 'admin-settings-network-facts'
})
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get(
		'/admin/api/settings/network-facts',
		({ admin }) => {
			const ctx = assertAuth(admin);
			assertSuperAdmin(ctx);
			return networkFactsStatus(now().getTime());
		},
		{ response: { 200: NetworkFactsStatusResponse } }
	);
