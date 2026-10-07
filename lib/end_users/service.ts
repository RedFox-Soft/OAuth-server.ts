import { getBucketGroupStore, getUserStore } from '../adapters/index.js';
import {
	DuplicateEndUserError,
	type EndUserPatch,
	type EndUserProfile,
	type User,
	type UserBucket
} from '../adapters/types.js';
import { cascadeForAccount, type CascadeResult } from '../helpers/cascade.js';
import { emailScopedId } from '../helpers/email_scoped_id.js';
import { unusablePassword } from '../helpers/unusable_password.js';
import { notifyRelyingParties, revokeAccountAccess } from './revoke_access.js';

/*
 * Every change to an end user, whichever surface it arrives through — the admin API (and MCP, which
 * dispatches into it) today, provisioning tomorrow. The rules live here so they hold however a change
 * arrives; a surface only authenticates its caller, names it as an actor, and records the audit entry.
 *
 * Audit-first survives the move by inversion: each operation takes the surface's `record` and calls it
 * after every refusal and before the first write. So a refused change writes no entry, and no change is
 * written without one.
 */

export type EndUserActor =
	{ kind: 'admin' } | { kind: 'connection'; connectionId: string };

/* Called once, after every check has passed and before anything is written. */
export type RecordChange = () => Promise<unknown>;

export class EndUserError extends Error {
	readonly status: 404 | 409 | 422;

	constructor(status: 404 | 409 | 422, message: string) {
		super(message);
		this.name = 'EndUserError';
		this.status = status;
	}
}

/*
 * Names an account's stored claims may not carry. `findAccount` spreads the stored claims last, so the
 * first three would stand in for the account's identity — `sub` also feeds the pairwise derivation —
 * and the rest for what the server itself asserts about a token or a sign-in.
 */
export const RESERVED_CLAIMS: readonly string[] = [
	'sub',
	'email',
	'email_verified',
	'iss',
	'aud',
	'exp',
	'iat',
	'nbf',
	'jti',
	'nonce',
	'azp',
	'acr',
	'amr',
	'auth_time',
	'sid',
	'at_hash',
	'c_hash',
	/* Always the user's actual bucket groups (lib/addon/account.ts); a stored value would forge authorization. */
	'groups'
];

function assertClaimsAssignable(claims: Record<string, unknown> | undefined) {
	if (!claims) return;
	const reserved = Object.keys(claims).filter((name) =>
		RESERVED_CLAIMS.includes(name)
	);
	if (reserved.length) {
		throw new EndUserError(
			422,
			`claims the server derives cannot be set on an account: ${reserved.join(', ')}`
		);
	}
}

/*
 * An external identifier names something inside a provisioning domain (RFC 7643 §3.1); without the
 * connection that issued it, it names nothing and its uniqueness cannot be scoped.
 */
function assertExternalIdScoped(
	externalId: string | undefined,
	provisionedBy: string | undefined
) {
	if (externalId !== undefined && provisionedBy === undefined) {
		throw new EndUserError(
			422,
			'an external identifier needs the connection that manages the user'
		);
	}
}

/* The store's uniqueness refusal, in the words the admin API has always used for the email case. */
function duplicateAsError(error: unknown): never {
	if (error instanceof DuplicateEndUserError) {
		throw new EndUserError(409, `${error.field} already exists`);
	}
	throw error;
}

async function existing(bucketId: string, id: string): Promise<User> {
	const user = await getUserStore(bucketId).find(id);
	if (!user) throw new EndUserError(404, 'user not found');
	return user;
}

/*
 * Who may change this record. A provisioned user's source of truth is the connection that provisioned it, so an
 * administrator here is refused — a local edit would be overwritten on the connection's next sync, silently
 * (IPSIE AL2). A connection reaches only its own users; another connection's, or a local one, does not exist
 * as far as it can tell. The local lock is not a change of this kind and is not checked here.
 */
function assertActorMayChange(actor: EndUserActor, user: User): void {
	if (actor.kind === 'admin') {
		if (user.provisionedBy !== undefined) {
			throw new EndUserError(
				409,
				`user is managed by connection ${user.provisionedBy}`
			);
		}
		return;
	}
	if (user.provisionedBy !== actor.connectionId) {
		throw new EndUserError(404, 'user not found');
	}
}

export interface CreateEndUserInput {
	/* Allocated by the caller so the audit entry can name the account before it exists. */
	id: string;
	email: string;
	/* Absent ⇒ an account no password opens (sign-in through federation, or a reset later). */
	password?: string;
	verified?: boolean;
	claims?: Record<string, unknown>;
	userName?: string;
	externalId?: string;
	profile?: EndUserProfile;
	/* Absent ⇒ active. A new account holds no session or token, so creating it inactive ends nothing. */
	active?: boolean;
}

export async function createEndUser(
	bucket: UserBucket,
	actor: EndUserActor,
	input: CreateEndUserInput,
	record: RecordChange
): Promise<User> {
	assertClaimsAssignable(input.claims);
	const provisionedBy =
		actor.kind === 'connection' ? actor.connectionId : undefined;
	assertExternalIdScoped(input.externalId, provisionedBy);

	const store = getUserStore(bucket._id);
	if (await store.findByEmail(input.email)) {
		throw new EndUserError(409, 'email already exists');
	}
	const hash =
		input.password === undefined
			? await unusablePassword()
			: await Bun.password.hash(input.password);

	await record();
	/*
	 * One insert carrying every identity field, so the unique indexes decide a race for a username or an
	 * external identifier atomically. A follow-up update — what this used to do — left the account behind
	 * without the colliding field, and a provisioning client retrying the refused create then collided on the
	 * email of that half-made account for ever (specs/070 R13).
	 */
	return store
		.create(input.email, hash, input.verified ?? true, input.id, {
			claims: input.claims,
			userName: input.userName,
			externalId: input.externalId,
			profile: input.profile,
			provisionedBy,
			active: input.active
		})
		.catch(duplicateAsError);
}

export interface UpdateEndUserInput {
	active?: boolean;
	claims?: Record<string, unknown>;
	email?: string;
	userName?: string;
	externalId?: string;
	profile?: EndUserProfile;
	/*
	 * Honoured for a connection only: whether its addresses are verified is the connection's email trust
	 * policy, and an administrator does not assert verification here.
	 */
	verified?: boolean;
}

/*
 * The record after an update, and — when the update took the user from able to sign in to unable — the report
 * of the access that ended with it.
 */
export interface UpdatedEndUser {
	user: User;
	revoked?: CascadeResult;
}

export async function updateEndUser(
	bucket: UserBucket,
	actor: EndUserActor,
	id: string,
	input: UpdateEndUserInput,
	record: RecordChange
): Promise<UpdatedEndUser> {
	assertClaimsAssignable(input.claims);
	const user = await existing(bucket._id, id);
	assertActorMayChange(actor, user);
	assertExternalIdScoped(input.externalId, user.provisionedBy);

	const patch: EndUserPatch = { ...input };
	if (actor.kind !== 'connection') delete patch.verified;
	/*
	 * A new login address is not verified by having been typed. Left as it was, a changed address would
	 * inherit the old one's verification — and the password-reset door mails whatever address is on file.
	 */
	if (
		input.email !== undefined &&
		input.email.toLowerCase() !== user.email &&
		patch.verified === undefined
	) {
		patch.verified = false;
	}

	await record();
	const updated = await getUserStore(bucket._id)
		.update(id, patch)
		.catch(duplicateAsError);
	if (!updated) throw new EndUserError(404, 'user not found');

	/*
	 * Written first, swept second: from the write on, account resolution refuses the user, so a sweep that
	 * fails partway leaves residue nobody can use. Deactivating an already inactive user sweeps again, which is
	 * how an operator retries after a partial failure.
	 */
	if (input.active === false) {
		return { user: updated, revoked: await revokeAccountAccess(id) };
	}
	return { user: updated };
}

export async function resetEndUserPassword(
	bucket: UserBucket,
	actor: EndUserActor,
	id: string,
	password: string,
	record: RecordChange
): Promise<void> {
	assertActorMayChange(actor, await existing(bucket._id, id));
	const hash = await Bun.password.hash(password);
	await record();
	await getUserStore(bucket._id).update(id, { password: hash });
}

/*
 * Audit, then destroy the principal, then cascade; a failed sweep is reported, never rolled back.
 *
 * The email-scoped id is computed before the row goes, because the areas it addresses (VerificationResend,
 * PasswordResetThrottle, LoginThrottle) record nothing else that would find them afterwards.
 */
export async function removeEndUser(
	bucket: UserBucket,
	actor: EndUserActor,
	id: string,
	record: RecordChange
): Promise<CascadeResult> {
	const user = await existing(bucket._id, id);
	assertActorMayChange(actor, user);
	const scopedId = user.email ? emailScopedId(bucket._id, user.email) : null;
	await record();
	/* Told while the sessions still exist; the cascade below destroys them, and their `sid` with them. */
	await notifyRelyingParties(id);
	/* Before the account, so no membership outlives it: a deleted user is in no group (specs/071 FR-004). */
	await getBucketGroupStore().removeUser(bucket._id, id);
	await getUserStore(bucket._id).destroy(id);
	return cascadeForAccount(id, scopedId);
}

/*
 * An administrator's emergency block. Allowed on any user, provisioned ones included — that is its reason to
 * exist: an incident response must not wait for an external system to act, and the provisioning connection
 * cannot undo it, because nothing a connection sends reaches this field (a deliberate departure from IPSIE AL2,
 * which otherwise forbids local changes to provisioned users; it touches sign-in only, never the profile).
 *
 * Locking an already locked user replaces the reason and sweeps again, which is how an operator retries after a
 * partial sweep.
 */
export async function lockEndUser(
	bucket: UserBucket,
	id: string,
	lock: { by: string; reason: string },
	record: RecordChange
): Promise<UpdatedEndUser> {
	await existing(bucket._id, id);
	await record();
	const locked = await getUserStore(bucket._id).update(id, {
		lockedLocally: { at: new Date(), by: lock.by, reason: lock.reason }
	});
	if (!locked) throw new EndUserError(404, 'user not found');
	return { user: locked, revoked: await revokeAccountAccess(id) };
}

/*
 * Ends a user's access everywhere without changing the account: no flag is written, so the user may sign in
 * again at once and consents afresh. What an administrator's "sign out everywhere" does, and what a bucket's
 * upstream identity provider asks for through global token revocation (specs/072) — one operation, so the two
 * cannot drift apart. Allowed on a provisioned user: it ends access, it edits nothing the connection owns.
 */
export async function revokeEndUserAccess(
	bucket: UserBucket,
	id: string,
	record: RecordChange
): Promise<UpdatedEndUser> {
	const user = await existing(bucket._id, id);
	await record();
	return { user, revoked: await revokeAccountAccess(id) };
}

/*
 * Hands a local user to a provisioning connection: the administrator's answer when the directory a bucket
 * now provisions from already has people in it (specs/070 FR-007a). Explicit and audited, never automatic —
 * a connection taking over an existing account by matching its email is the takeover the series refuses.
 *
 * The user keeps its id, sessions, grants and federated links; from here on it is read-only to
 * administrators and visible to that connection's SCIM requests. One update, so the unique indexes refuse a
 * colliding username or external identifier without leaving the user half-assigned.
 */
export async function assignEndUserToConnection(
	bucket: UserBucket,
	id: string,
	assignment: { connectionId: string; userName?: string; externalId?: string },
	record: RecordChange
): Promise<User> {
	const user = await existing(bucket._id, id);
	if (user.provisionedBy !== undefined) {
		throw new EndUserError(
			409,
			`user is managed by connection ${user.provisionedBy}`
		);
	}
	if (
		assignment.userName === undefined &&
		assignment.externalId === undefined
	) {
		throw new EndUserError(
			422,
			'name the user as the directory knows it: a userName, an externalId, or both'
		);
	}
	const patch: EndUserPatch = { provisionedBy: assignment.connectionId };
	if (assignment.userName !== undefined) patch.userName = assignment.userName;
	if (assignment.externalId !== undefined)
		patch.externalId = assignment.externalId;

	await record();
	const assigned = await getUserStore(bucket._id)
		.update(id, patch)
		.catch(duplicateAsError);
	if (!assigned) throw new EndUserError(404, 'user not found');
	return assigned;
}

/* Lifts the lock and restores nothing: the user signs in afresh, and only if also active. */
export async function unlockEndUser(
	bucket: UserBucket,
	id: string,
	record: RecordChange
): Promise<User> {
	await existing(bucket._id, id);
	await record();
	const unlocked = await getUserStore(bucket._id).update(id, {
		lockedLocally: undefined
	});
	if (!unlocked) throw new EndUserError(404, 'user not found');
	return unlocked;
}
