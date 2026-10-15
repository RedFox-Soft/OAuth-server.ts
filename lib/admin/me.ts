import { Elysia } from 'elysia';

import { getBucketStore, getUserStore } from '../adapters/index.js';
import { sendOnDemand } from '../verification/challenge.js';
import {
	resolveAdmin,
	assertAuth,
	AdminError,
	adminErrorBody
} from './auth/rbac.js';
import { meCan } from './auth/can.js';
import { meView } from './me_view.js';
import { ADMIN_BUCKET_ID } from './consts.js';
import { planRightsOf } from '../plans/rights.js';

/*
 * Who the caller is, as the admin plane resolved them: id, email, whether a super administrator, bucket
 * and the groups they belong to.
 *
 * Its own plugin rather than an inline route on `adminApp`, because two surfaces mount it. It was
 * inline until the MCP control plane needed it: the `whoami` tool re-dispatches into this route, and
 * `lib/mcp/dispatch.ts` composes route plugins rather than `adminApp` — importing `adminApp` pulls
 * `renderAdminShell` and with it React and antd's CSS-in-JS, measured at ~86s to load against ~350ms
 * for the plugins.
 */
export const meRoutes = new Elysia({ name: 'admin-me' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	/*
	 * `verified` beside who the caller is, so the console can offer "verify my address" where it matters:
	 * requiring verification of administrators is refused until the person requiring it has proven theirs.
	 */
	.get('/admin/api/me', async ({ admin }) => {
		const ctx = assertAuth(admin);
		const account = await getUserStore(ADMIN_BUCKET_ID).find(ctx.userId);
		/*
		 * `can`: what the caller may create, and whether the instance-wide surfaces are theirs — with what their
		 * plan still allows them to create (specs/102).
		 */
		return {
			...meView(ctx),
			verified: account?.verified === true,
			can: { ...meCan(ctx), ...(await planRightsOf(ctx)) }
		};
	})
	/*
	 * Mails the caller a verification message for their own address, in the administrators' bucket's
	 * current method. Always a fresh one, within the cooldown and daily cap: pressing the button says the
	 * last message did not arrive.
	 *
	 * Not audited, and listed with that reason in `excludedAdminRoutes`: it changes no managed entity. It
	 * reaches only the caller's own mailbox, and the account becomes verified at the public verification
	 * endpoint, where the person holding the mailbox completes it.
	 */
	.post('/admin/api/me/verification', async ({ admin, set }) => {
		const ctx = assertAuth(admin);
		const users = getUserStore(ADMIN_BUCKET_ID);
		const account = await users.find(ctx.userId);
		if (!account) throw new AdminError(404, 'no administrator account');
		if (account.verified) return { alreadyVerified: true };
		const bucket = await getBucketStore().find(ADMIN_BUCKET_ID);
		if (!bucket)
			throw new AdminError(500, "the administrators' project is missing");

		const sent = await sendOnDemand(account, bucket, {
			reuseOutstanding: false
		});
		switch (sent.outcome) {
			case 'sent':
			case 'outstanding':
				return {
					sent: true,
					method: sent.method,
					...(sent.method === 'code'
						? {
								codeUrl: `/verify-email/code?ref=${encodeURIComponent(sent.id)}`
							}
						: {})
				};
			// `message` beside the reason code, so a refusal reads like every other admin refusal.
			case 'rate_limited':
				set.status = 429;
				return {
					sent: false,
					reason: sent.outcome,
					message:
						'A message was sent recently. Check your inbox, or try again in a minute.'
				};
			case 'mail_not_configured':
				set.status = 409;
				return {
					sent: false,
					reason: sent.outcome,
					message: 'Mail delivery is not configured, so no message can be sent.'
				};
			case 'delivery_failed':
				set.status = 502;
				return {
					sent: false,
					reason: sent.outcome,
					message: 'The message could not be sent. Try again later.'
				};
		}
	});
