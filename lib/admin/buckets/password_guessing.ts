import { Elysia } from 'elysia';

import { COUNT_DAYS, countsFor } from '../../attacker_list/counters.js';
import { listState } from '../../attacker_list/state.js';
import { callerAddressOf } from '../../helpers/caller_address.js';
import { now } from '../../telemetry/clock.js';
import { ADMIN_BUCKET_ID } from '../consts.js';
import {
	AdminError,
	adminErrorBody,
	assertAuth,
	resolveAdmin
} from '../auth/rbac.js';
import { loadBucketForSettings } from './access.js';
import { PasswordGuessingResponse } from './schema.js';

/*
 * What a project does with FoxTrust's attacker list and the numbers it decides with (specs/125): its choice, its
 * exempt networks, the list's state in the answering process, and the last 7 days of password sign-ins from listed
 * addresses. A read, open to whoever may read the project, a scheduled one included. The choice itself is changed
 * through the project PATCH, where Refuse is previewed and the administrators' project refuses it.
 */
export const passwordGuessingRoutes = new Elysia({
	name: 'admin-password-guessing'
})
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get(
		'/admin/api/projects/:id/password-guessing',
		async ({ admin, params, request }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForSettings(ctx, params.id, 'read');
			const caller = callerAddressOf(request);
			return {
				mode: bucket.passwordGuessing?.mode ?? 'count',
				modeIsDefault: bucket.passwordGuessing === undefined,
				exempt: bucket.passwordGuessing?.exempt ?? [],
				list: listState(now().getTime()),
				days: COUNT_DAYS,
				counts: await countsFor(bucket._id),
				refuseAvailable: bucket._id !== ADMIN_BUCKET_ID,
				yourAddress: caller.from === 'unattributed' ? null : caller.address
			};
		},
		{ response: { 200: PasswordGuessingResponse } }
	);
