import { Elysia } from 'elysia';

import {
	assertAuth,
	assertSuperAdmin,
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../../auth/rbac.js';
import { attackReportsStatus } from '../../../attack_reports/status.js';
import { AttackReportsStatusResponse } from './schema.js';

/*
 * The attack reporting card (specs/114): read-only. The switch is the ordinary `attackReports.enabled` catalog
 * entry, saved and audited through the generic settings route, so nothing here mutates.
 */
export const attackReportsSettingsRoutes = new Elysia({
	name: 'admin-settings-attack-reports'
})
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get(
		'/admin/api/settings/attack-reports',
		async ({ admin }) => {
			const ctx = assertAuth(admin);
			// The report names addresses that attacked the whole instance; no project administrator has a view of it.
			assertSuperAdmin(ctx);
			return attackReportsStatus();
		},
		{ response: { 200: AttackReportsStatusResponse } }
	);
