import { Elysia } from 'elysia';

import { addressLookupStatus } from '../../../address_lookup/status.js';
import { now } from '../../../telemetry/clock.js';
import {
	assertAuth,
	assertSuperAdmin,
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../../auth/rbac.js';
import { AddressLookupStatusResponse } from './schema.js';

/*
 * Whether this server has a FoxTrust key for looking up owners and locations, and if not why (specs/136 FR-012).
 * Super administrators only, like the network facts' card: the setting is instance-wide, and the status names this
 * instance's id and public key.
 */
export const addressLookupSettingsRoutes = new Elysia({
	name: 'admin-settings-address-lookup'
})
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get(
		'/admin/api/settings/address-lookup',
		async ({ admin }) => {
			const ctx = assertAuth(admin);
			assertSuperAdmin(ctx);
			return addressLookupStatus(now());
		},
		{ response: { 200: AddressLookupStatusResponse } }
	);
