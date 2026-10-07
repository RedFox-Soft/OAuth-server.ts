import {
	checkedAdapter,
	getGroupStore,
	getProvisioningConnectionStore,
	getUserStore
} from '../adapters/index.js';
import type {
	DeprovisioningHold,
	DeprovisioningThreshold,
	ProvisioningConnection,
	UserBucket
} from '../adapters/types.js';
import { recordConnectionAudit } from '../admin/audit/record.js';
import { ADMIN_BUCKET_ID, UNASSIGNED_GROUP_ID } from '../admin/consts.js';
import { superAdminIds } from '../admin/super_admins.js';
import { ISSUER } from '../configs/env.js';
import { eventBus } from '../event_bus.js';
import epochTime from '../helpers/epoch_time.js';
import { sendDeprovisioningHeldEmail } from '../mail/send.js';
import { ScimError } from '../scim/errors.js';
import { DeprovisionSlotPayload } from './tally_types.js';

/*
 * The mass-deprovisioning guard (specs/072 User Story 4): a connection with a `threshold` is admitted at most
 * `count` deprovisionings in any `windowSeconds`, and the first one beyond that holds the connection until an
 * administrator of the bucket releases it. Called by the SCIM user routes for a deprovisioning only — a
 * deactivation that changes a stored active user, or the deletion of an existing one — and nowhere else, so
 * nothing an administrator does and no other SCIM request can count or be refused here.
 */

/*
 * Long enough that a connection idle for a while keeps its sequence, short enough that a deleted connection's
 * counter is reaped on its own. Longer than any window (7 days), so a counter never outlives a slot it numbered
 * and restarts at a number whose slot is still live.
 */
const COUNTER_LIFETIME_SECONDS = 30 * 24 * 60 * 60;

/*
 * Minutes, not hours: Okta retries a 429 on its own after `Retry-After` and documents only a short backoff,
 * and Entra ignores the header and retries the escrowed operation on its own schedule (research R8).
 */
const RETRY_AFTER_SECONDS = '300';

const HELD_DETAIL =
	'Deprovisioning from this connection is held by its mass-deprovisioning guard until an administrator releases it.';

const slots = () => checkedAdapter('DeprovisionSlot', DeprovisionSlotPayload);

/*
 * Answers the next sequence number of this generation of the tally. `increment` needs a record, so the counter
 * is created first; `create` is insert-if-absent, so every caller but the first is a no-op. A counter reaped
 * between the two writes is created again once; past that the request fails as a defect and the directory
 * retries it, rather than guessing a number.
 */
async function nextSequence(counterId: string): Promise<number> {
	for (let attempt = 0; attempt < 2; attempt += 1) {
		await slots().create(
			counterId,
			{ n: 0, exp: epochTime() + COUNTER_LIFETIME_SECONDS },
			COUNTER_LIFETIME_SECONDS
		);
		const seq = await slots().increment(
			counterId,
			'n',
			COUNTER_LIFETIME_SECONDS
		);
		if (seq !== undefined) return seq;
	}
	throw new Error(`deprovisioning tally counter ${counterId} vanished`);
}

/*
 * Claims one of the threshold's `count` slots for `windowSeconds`, answering whether a slot was free.
 *
 * Exact by construction rather than by a count-then-write: the counter hands every caller a distinct sequence
 * number in one atomic write, and the slot it names (`seq mod count`) is taken by an insert-if-absent that
 * treats an expired record as free — both single atomic writes on all three backends. Each admitted
 * deprovisioning therefore holds one of `count` slots for exactly `windowSeconds`, so at most `count` are
 * admitted in any window of that length, under any concurrency and across server instances (FR-019).
 *
 * It errs only toward stopping sooner, and that is accepted: a refused claim still burns a sequence number;
 * two concurrent deactivations of the same user both read `active: true` and both claim; a claim whose write
 * then fails stays claimed. None can admit more than `count`.
 *
 * A release or a threshold change moves `tallyEpoch` on, which renames every id here: the count starts afresh
 * and the previous generation's records are left to expire.
 */
async function claimSlot(
	connection: ProvisioningConnection,
	threshold: DeprovisioningThreshold
): Promise<boolean> {
	const prefix = `${connection._id}:${connection.tallyEpoch ?? 0}`;
	const seq = await nextSequence(`${prefix}:counter`);
	return slots().create(
		`${prefix}:${seq % threshold.count}`,
		{ exp: epochTime() + threshold.windowSeconds },
		threshold.windowSeconds
	);
}

/*
 * The refusal of every deprovisioning while a connection is held. A 429 because it is the one status both
 * supported directories treat as temporary: Okta retries it unattended where it turns a 5xx into a task an
 * administrator must retry by hand, and a 5xx would also be captured as a defect, which this is not. 401, 403
 * and 404 are never used: Entra quarantines a job on them regardless of count (research R8).
 *
 * This is a deliberate departure from IPSIE AL SCIM §5.1–§5.2 (CONFORMANCE.md, "SCIM provisioning"), which
 * expects a deactivation or deletion to end the user's access as soon as it arrives: while held, a leaver keeps
 * their access until an administrator releases the hold. The connection's `threshold` is the switch that
 * isolates the departure (Constitution Principle I) — absent by default, so an unguarded connection conforms,
 * and set deliberately per connection by an administrator who chooses the brake over immediacy.
 */
function heldRefusal(bucket: UserBucket, connection: ProvisioningConnection) {
	eventBus.emit('provisioning.held.refused', {
		bucketId: bucket._id,
		connectionId: connection._id
	});
	return new ScimError(429, undefined, HELD_DETAIL, {
		'Retry-After': RETRY_AFTER_SECONDS
	});
}

/*
 * The people who can release the hold: the active administrators of the group that owns the bucket. The
 * reserved `unassigned` group has no members, so a bucket it owns alerts the super administrators instead.
 */
async function alertRecipients(bucket: UserBucket): Promise<string[]> {
	let ids: string[];
	if (bucket.ownerGroupId === UNASSIGNED_GROUP_ID) {
		ids = await superAdminIds();
	} else {
		const group = await getGroupStore().find(bucket.ownerGroupId);
		ids = group?.members.map((m) => m.userId) ?? [];
	}
	if (ids.length === 0) return [];
	const users = await getUserStore(ADMIN_BUCKET_ID).findMany(ids);
	return users.filter((u) => u.active && u.email).map((u) => u.email);
}

/*
 * Never awaited by the request and never thrown: the hold is already recorded, and the console, the MCP view
 * and the audit trail carry it whether or not mail goes (FR-022). Each recipient is mailed separately, so one
 * refused address does not cost the others their alert, and none learns who else was told.
 */
async function alertAdministrators(
	bucket: UserBucket,
	connection: ProvisioningConnection,
	hold: DeprovisioningHold
): Promise<void> {
	const failed = (reason: unknown) =>
		eventBus.emit('provisioning.hold.alert_failed', {
			bucketId: bucket._id,
			connectionId: connection._id,
			reason: reason instanceof Error ? reason.message : String(reason)
		});
	try {
		const recipients = await alertRecipients(bucket);
		await Promise.all(
			recipients.map((to) =>
				sendDeprovisioningHeldEmail({
					email: to,
					connectionName: connection.displayName,
					bucketName: bucket.name,
					since: hold.since,
					count: hold.count,
					consoleUrl: `${ISSUER}/admin`
				}).catch(failed)
			)
		);
	} catch (error) {
		failed(error);
	}
}

/*
 * Holds the connection when this request is the first to find the threshold reached. `holdIfFree` is one
 * conditional write, so of a burst of requests tripping it together exactly one is told it set the hold, and
 * only that one records it and alerts: a hundred refusals must not mail the administrators a hundred times.
 *
 * The audit entry follows the write rather than preceding it, the one place this module departs from
 * audit-first: written before, every refused request in the burst would record a hold that only one of them
 * set. A failed audit write still fails the request (the SCIM plugin answers 500 and records the defect), and
 * the hold it leaves is visible on the connection and refuses the directory's retry.
 */
async function hold(
	bucket: UserBucket,
	connection: ProvisioningConnection,
	threshold: DeprovisioningThreshold
): Promise<void> {
	const held: DeprovisioningHold = {
		since: new Date(),
		count: threshold.count
	};
	if (
		!(await getProvisioningConnectionStore().holdIfFree(connection._id, held))
	) {
		return;
	}
	await recordConnectionAudit(
		connection._id,
		'provisioning.connection.update',
		connection._id,
		{
			attributes: ['hold'],
			targetScope: bucket._id,
			ownerGroupId: bucket.ownerGroupId
		}
	);
	eventBus.emit('provisioning.held', {
		bucketId: bucket._id,
		connectionId: connection._id,
		count: threshold.count
	});
	void alertAdministrators(bucket, connection, held);
}

/*
 * Admits one deprovisioning from `connection`, or throws the 429 that refuses it. Called after every other
 * refusal of the request and before anything of it is written, so a refused request changes nothing.
 *
 * `connection` is the record the SCIM principal loaded for this request: a hold it already shows is refused
 * without touching the tally, and a hold set since by a concurrent request is found by the claim failing.
 */
export async function admitDeprovisioning(
	bucket: UserBucket,
	connection: ProvisioningConnection
): Promise<void> {
	if (connection.hold) throw heldRefusal(bucket, connection);
	const threshold = connection.threshold;
	if (!threshold) return;
	if (await claimSlot(connection, threshold)) return;
	await hold(bucket, connection, threshold);
	throw heldRefusal(bucket, connection);
}
