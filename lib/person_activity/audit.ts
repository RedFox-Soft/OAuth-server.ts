import { adminAuditStore } from '../adapters/index.js';
import type { UserBucket } from '../adapters/types.js';
import { recordAdminAudit } from '../admin/audit/record.js';
import type { AdminContext } from '../admin/auth/rbac.js';

/*
 * Who read a person's activity (specs/133 FR-025): one audit entry per reader, person and UTC day, an agent's read
 * naming the agent. A stolen administrator token or agent reading everyone's addresses leaves a trail; an
 * administrator reading the same person ten times a day leaves one line, so the reads do not bury the changes.
 *
 * The entry is looked for before it is written. A per-process memo makes two concurrent reads in this process write
 * one; two processes answering the same reader in the same instant may each write one, which is accepted.
 */

const pending = new Map<string, Promise<void>>();

function startOfDay(at: Date): Date {
	return new Date(
		Date.UTC(at.getUTCFullYear(), at.getUTCMonth(), at.getUTCDate())
	);
}

async function recordOnce(
	ctx: AdminContext,
	bucket: UserBucket,
	accountId: string,
	since: Date
): Promise<void> {
	const { entries } = await adminAuditStore.list({
		actor: ctx.userId,
		action: 'enduser.activity.read',
		targetId: accountId,
		targetScope: bucket._id,
		/* An agent is a reader of its own: its read is recorded even when its administrator read in the console. */
		...(ctx.viaClientId
			? { viaClientId: ctx.viaClientId }
			: { viaSurface: 'console' }),
		from: since,
		limit: 1
	});
	if (entries.length > 0) return;
	await recordAdminAudit(ctx, 'enduser.activity.read', accountId, {
		targetScope: bucket._id,
		ownerGroupId: bucket.ownerGroupId
	});
}

export async function recordActivityRead(
	ctx: AdminContext,
	bucket: UserBucket,
	accountId: string
): Promise<void> {
	const since = startOfDay(new Date());
	const key = [
		ctx.userId,
		ctx.viaClientId ?? '',
		bucket._id,
		accountId,
		since.toISOString()
	].join('\u0000');
	let running = pending.get(key);
	if (!running) {
		running = recordOnce(ctx, bucket, accountId, since).finally(() => {
			pending.delete(key);
		});
		pending.set(key, running);
	}
	await running;
}
