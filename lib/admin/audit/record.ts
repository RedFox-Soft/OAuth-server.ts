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
	/*
	 * The group this entry belongs to, and the only thing a group-scoped read selects on.
	 *
	 * Passed explicitly rather than taken from the acting administrator's active scope, because the two
	 * differ exactly where it matters: a super administrator acts on any group's container while their
	 * own scope is empty, and an entry attributed to their scope would vanish from the trail the owning
	 * group can read. Omitted for an instance-wide action, which belongs to no group.
	 */
	ownerGroupId?: string;
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
		detail,
		/*
		 * Present only when the action arrived through the MCP control plane, carrying the agent's OAuth
		 * client. The actor stays the administrator — the constitution requires an agent's action to be
		 * attributable to the agent *and* the authorizing principal, and recording the agent alongside
		 * them is what satisfies both without redefining what `actorId` means.
		 *
		 * Absence means the console, which is why nothing needs backfilling for the entries written
		 * before agents existed.
		 */
		viaClientId: ctx.viaClientId
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
	viaClientId?: string;
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
			...(input.detail.ownerGroupId === undefined
				? {}
				: { ownerGroupId: input.detail.ownerGroupId }),
			// Sorted so two requests setting the same fields in a different order read identically.
			...(input.detail.attributes === undefined
				? {}
				: { attributes: [...input.detail.attributes].sort() }),
			/*
			 * `viaSurface` is stored rather than inferred from `viaClientId`, because inferring "this was
			 * an agent" from a client id would make every reader carry a list of which client ids are
			 * agents — and that list changes.
			 */
			...(input.viaClientId === undefined
				? {}
				: { viaClientId: input.viaClientId, viaSurface: 'mcp' as const })
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
