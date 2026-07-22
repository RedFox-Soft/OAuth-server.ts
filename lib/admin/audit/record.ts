import { adminAuditStore } from '../../adapters/index.js';
import type { AdminAuditEntry } from '../../adapters/types.js';
import type { AdminContext } from '../auth/rbac.js';

// Write one append-only audit entry for a state-changing admin action. Called *before* the
// underlying mutation (audit-first): a mutation must not be reported successful unless its
// audit entry was recorded (constitution: immutable audit log for every admin action). If
// the audit write throws, the caller surfaces the error and never applies the mutation.
export function recordAdminAudit(
	ctx: AdminContext,
	action: string,
	targetType: string,
	targetId: string
): Promise<AdminAuditEntry> {
	return adminAuditStore.record({
		actorId: ctx.userId,
		actorEmail: ctx.email,
		action,
		targetType,
		targetId
	});
}
