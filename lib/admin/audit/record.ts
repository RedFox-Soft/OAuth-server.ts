import { adminAuditStore } from '../../adapters/index.js';
import type { AdminAuditEntry } from '../../adapters/types.js';
import {
	auditTargetTypeFor,
	BOOTSTRAP_ACTOR,
	type AuditAction
} from '../../consts/admin_audit_routes.js';
import { AdminError, type AdminContext } from '../auth/rbac.js';

export interface AuditDetail {
	/* Names of the fields the request set — never their values, so no secret can reach the trail. */
	attributes?: string[];
	/* The container the target id resolves within, in practice a bucket. */
	targetScope?: string;
}

/*
 * Raised when the trail refuses a write. A 500 because nothing about the request was wrong, and a
 * message the caller can act on: the change did NOT happen.
 *
 * An AdminError subclass deliberately — every admin route module already renders those in the
 * `{ error, message }` shape, so this reaches an operator as a stated reason rather than falling
 * through to the OAuth (RFC 6749) error handler the protocol routes use, or to an opaque framework 500.
 */
export class AuditUnavailableError extends AdminError {
	constructor(readonly reason: unknown) {
		super(500, 'audit unavailable — the change was not applied');
	}
}

/*
 * Write one append-only audit entry for a state-changing admin action. Called *before* the underlying
 * mutation (audit-first): a mutation must not be reported successful unless its audit entry was
 * recorded (constitution: immutable audit log for every admin action). A rejected write aborts the
 * request, so the mutation never runs.
 *
 * Two consequences of that ordering are worth stating, because they decide how an entry should be read:
 *
 * 1. An entry attests that an *authorized* actor reached the point of applying this change — not that
 *    the change took effect. A late failure (not-found, a uniqueness conflict, the last-super-admin
 *    guard) can follow a written entry. The read surface says so.
 * 2. The write belongs inside the handler, after authentication and authorization, and must never move
 *    to a route-level plugin. Authorization happens in the handler body here, so a plugin would record
 *    entries for unauthenticated callers — an unauthenticated write path into permanent, append-only
 *    storage.
 *
 * `targetType` is resolved from the audited-routes table rather than passed in, and `action` is typed
 * as that table's union, so a route absent from the table cannot record and a target type cannot be
 * mistyped.
 */
export function recordAdminAudit(
	ctx: AdminContext,
	action: AuditAction,
	targetId: string,
	detail: AuditDetail = {}
): Promise<AdminAuditEntry> {
	return write({
		actorId: ctx.userId,
		actorEmail: ctx.email,
		action,
		targetId,
		detail
	});
}

/*
 * First-run setup has no session, so there is no administrator to attribute. The bootstrap sentinel is
 * recorded instead — distinguishable from every real actor without a lookup, since a real email always
 * contains '@' and neither a real id nor a real email ever contains ':'.
 */
export function recordBootstrapAudit(
	action: AuditAction,
	targetId: string,
	detail: AuditDetail = {}
): Promise<AdminAuditEntry> {
	return write({
		actorId: BOOTSTRAP_ACTOR,
		actorEmail: BOOTSTRAP_ACTOR,
		action,
		targetId,
		detail
	});
}

async function write(input: {
	actorId: string;
	actorEmail: string;
	action: AuditAction;
	targetId: string;
	detail: AuditDetail;
}): Promise<AdminAuditEntry> {
	try {
		return await adminAuditStore.record({
			actorId: input.actorId,
			actorEmail: input.actorEmail,
			action: input.action,
			targetType: auditTargetTypeFor(input.action),
			targetId: input.targetId,
			...(input.detail.targetScope === undefined
				? {}
				: { targetScope: input.detail.targetScope }),
			// Sorted so two requests setting the same fields in a different order read identically.
			...(input.detail.attributes === undefined
				? {}
				: { attributes: [...input.detail.attributes].sort() })
		});
	} catch (err) {
		/*
		 * Logged as well as thrown: a trail that has stopped accepting entries is otherwise invisible
		 * until someone goes looking for records that were never written — the failure mode with the
		 * longest gap between cause and discovery.
		 */
		console.error(
			`admin audit write failed for ${input.action} on ${input.targetId}; change not applied`,
			err
		);
		throw new AuditUnavailableError(err);
	}
}
