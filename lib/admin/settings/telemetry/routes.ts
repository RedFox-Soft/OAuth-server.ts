import { Elysia } from 'elysia';

import {
	assertAuth,
	assertSuperAdmin,
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../../auth/rbac.js';
import { telemetryStatus } from '../../../telemetry/status.js';
import { TelemetryStatusResponse } from './schema.js';

/*
 * The usage reporting card (specs/113): read-only. The switch is the ordinary `telemetry.enabled` catalog
 * entry, saved and audited through the generic settings route, so nothing here mutates.
 */
export const telemetrySettingsRoutes = new Elysia({
	name: 'admin-settings-telemetry'
})
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get(
		'/admin/api/settings/telemetry',
		async ({ admin }) => {
			const ctx = assertAuth(admin);
			// What leaves the instance is an instance-wide fact; no project administrator has a view of it.
			assertSuperAdmin(ctx);
			return telemetryStatus();
		},
		{ response: { 200: TelemetryStatusResponse } }
	);
