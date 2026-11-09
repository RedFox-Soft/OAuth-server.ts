import { Elysia } from 'elysia';

import { getBucketStore } from '../../../adapters/index.js';
import { listStatus } from '../../../attacker_list/state.js';
import { now } from '../../../telemetry/clock.js';
import {
	assertAuth,
	assertSuperAdmin,
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../../auth/rbac.js';
import { AttackerListStatusResponse } from './schema.js';

/*
 * The state of FoxTrust's attacker list in the process that answers (specs/125). Super administrators only, like
 * the attack reporting card beside it: the switch is instance-wide. `projectsUsing` is what turning attack reporting
 * off would take away, so the console can name it before asking.
 */
export const attackerListSettingsRoutes = new Elysia({
	name: 'admin-settings-attacker-list'
})
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get(
		'/admin/api/settings/attacker-list',
		async ({ admin }) => {
			const ctx = assertAuth(admin);
			assertSuperAdmin(ctx);
			const buckets = await getBucketStore().list();
			const using = buckets.filter(
				(bucket) => (bucket.passwordGuessing?.mode ?? 'count') !== 'nothing'
			);
			return {
				...listStatus(now().getTime()),
				projectsUsing: {
					count: using.length,
					refuse: using.filter(
						(bucket) => bucket.passwordGuessing?.mode === 'refuse'
					).length
				}
			};
		},
		{ response: { 200: AttackerListStatusResponse } }
	);
