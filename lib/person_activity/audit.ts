import { adminAuditStore } from '../adapters/index.js';
import type { UserBucket } from '../adapters/types.js';
import { recordAdminAudit } from '../admin/audit/record.js';
import type { AdminContext } from '../admin/auth/rbac.js';

/*
 * Who read a person's activity (specs/133 FR-025), or who an app or an API refused (specs/134 FR-022): one audit
 * entry per reader, target and UTC day, an agent's read naming the agent. A stolen administrator token or agent reading everyone's addresses leaves a trail; an
 * administrator reading the same person ten times a day leaves one line, so the reads do not bury the changes.
 *
 * The entry is looked for before it is written. A per-process memo makes two concurrent reads in this process write
 * one; two processes answering the same reader in the same instant may each write one, which is accepted.
 */

const pending = new Map<string, Promise<void>>();

/* The audited reads of people's activity: a person's timeline, and who an app or an API refused (specs/134). */
export type ActivityReadAction =
	| 'enduser.activity.read'
	| 'behindproxy.refusals.read'
	| 'resource.refusals.read';

function startOfDay(at: Date): Date {
	return new Date(
		Date.UTC(at.getUTCFullYear(), at.getUTCMonth(), at.getUTCDate())
	);
}

async function recordOnce(
	ctx: AdminContext,
	bucket: UserBucket,
	action: ActivityReadAction,
	targetId: string,
	since: Date
): Promise<void> {
	const { entries } = await adminAuditStore.list({
		actor: ctx.userId,
		action,
		targetId,
		targetScope: bucket._id,
		/* An agent is a reader of its own: its read is recorded even when its administrator read in the console. */
		...(ctx.viaClientId
			? { viaClientId: ctx.viaClientId }
			: { viaSurface: 'console' }),
		from: since,
		limit: 1
	});
	if (entries.length > 0) return;
	await recordAdminAudit(ctx, action, targetId, {
		targetScope: bucket._id,
		ownerGroupId: bucket.ownerGroupId
	});
}

/* One entry per reader, action, target and UTC day; an agent's read names the agent. */
export async function recordReadOnce(
	ctx: AdminContext,
	bucket: UserBucket,
	action: ActivityReadAction,
	targetId: string
): Promise<void> {
	const since = startOfDay(new Date());
	const key = [
		ctx.userId,
		ctx.viaClientId ?? '',
		bucket._id,
		action,
		targetId,
		since.toISOString()
	].join('\u0000');
	let running = pending.get(key);
	if (!running) {
		running = recordOnce(ctx, bucket, action, targetId, since).finally(() => {
			pending.delete(key);
		});
		pending.set(key, running);
	}
	await running;
}

export function recordActivityRead(
	ctx: AdminContext,
	bucket: UserBucket,
	accountId: string
): Promise<void> {
	return recordReadOnce(ctx, bucket, 'enduser.activity.read', accountId);
}
