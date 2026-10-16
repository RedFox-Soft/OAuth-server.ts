import { getBucketGroupStore, getUserStore } from '../adapters/index.js';
import {
	DuplicateEndUserError,
	type EndUserPatch,
	type EndUserProfile,
	type User,
	type UserBucket
} from '../adapters/types.js';
import { ApplicationConfig } from '../configs/application.js';
import { cascadeForAccount, type CascadeResult } from '../helpers/cascade.js';
import { emailScopedId } from '../helpers/email_scoped_id.js';
import epochTime from '../helpers/epoch_time.js';
import { RESERVED_CLAIMS } from '../consts/reserved_claims.js';
import { unusablePassword } from '../helpers/unusable_password.js';
import { mailDeliveryConfigured } from '../mail/mailer.js';
import {
	invite,
	inviteRetryAfter,
	type InviteOutcome
} from '../password_reset/challenge.js';
import { backchannelLogoutFor } from '../shared/destroy_session.js';
import { discardPending } from '../verification/challenge.js';
import { canSignIn } from './can_sign_in.js';
import { changedProfileFields, validateProfile } from './profile_validation.js';
import {
	endGrants,
	notifyRelyingParties,
	revokeAccountAccess
} from './revoke_access.js';
import { grantsIn, sessionsIn } from './sessions.js';
import { lookup, type Language } from '../i18n/languages.js';
import { storedLocaleRanges } from '../i18n/resolve.js';

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

/* What an update changed that its entry names: the profile fields an edit replaced, as `profile.<field>`. */
export interface UpdateRecordDetail {
	profileFields: string[];
}

export class EndUserError extends Error {
	readonly status: 404 | 409 | 422;
	/* The input field the refusal is about, when one field is the whole reason — so a form can mark it. */
	readonly field?: string;

	constructor(status: 404 | 409 | 422, message: string, field?: string) {
		super(message);
		this.name = 'EndUserError';
		this.status = status;
		if (field !== undefined) this.field = field;
	}
}

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
		throw new EndUserError(409, `${error.field} already exists`, error.field);
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
		throw new EndUserError(409, 'email already exists', 'email');
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
	return (
		store
			// Unproven unless the caller says otherwise (specs/104): a caller that forgets gets the honest answer.
			.create(input.email, hash, input.verified ?? false, input.id, {
				claims: input.claims,
				userName: input.userName,
				externalId: input.externalId,
				profile: input.profile,
				provisionedBy,
				active: input.active,
				passwordSet: input.password !== undefined
			})
			.catch(duplicateAsError)
	);
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
	record: (detail: UpdateRecordDetail) => Promise<unknown>
): Promise<UpdatedEndUser> {
	assertClaimsAssignable(input.claims);
	const user = await existing(bucket._id, id);
	assertActorMayChange(actor, user);
	assertExternalIdScoped(input.externalId, user.provisionedBy);
	/*
	 * An administrator writes a local person's profile through here (specs/089), and its values reach
	 * applications as standard claims, so they are held to what those claims allow. A connection's are not.
	 */
	if (actor.kind === 'admin' && input.profile !== undefined) {
		const refused = validateProfile(input.profile);
		if (refused) throw new EndUserError(422, refused.message, refused.field);
	}
	/*
	 * Refused before the record, so a taken address writes no entry: the store's unique index still decides a
	 * race, but the ordinary case of an address somebody already holds is a refusal, not an audited change.
	 */
	if (input.email !== undefined) {
		const holder = await getUserStore(bucket._id).findByEmail(input.email);
		if (holder && holder._id !== id) {
			throw new EndUserError(409, 'email already exists', 'email');
		}
	}

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

	await record({
		profileFields:
			input.profile === undefined
				? []
				: changedProfileFields(user.profile, input.profile)
	});
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

/*
 * Sets a password an administrator chose. With `signOut`, every session, grant and token the account holds
 * ends in the same request, after the write — what "I think someone else has this password" needs, and the
 * same sweep "sign out everywhere" runs, so the two cannot differ. Without it, existing sign-ins are kept.
 */
export async function resetEndUserPassword(
	bucket: UserBucket,
	actor: EndUserActor,
	id: string,
	password: string,
	record: RecordChange,
	options: { signOut?: boolean } = {}
): Promise<{ revoked?: CascadeResult }> {
	assertActorMayChange(actor, await existing(bucket._id, id));
	const hash = await Bun.password.hash(password);
	await record();
	await getUserStore(bucket._id).update(id, {
		password: hash,
		passwordSet: true
	});
	return options.signOut === true
		? { revoked: await revokeAccountAccess(id) }
		: {};
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

/*
 * Why an invitation cannot be sent in this bucket at all, whoever it is for: a bucket without a password door
 * has nothing to set, and without mail there is no message. Asked before an account is created to invite, so
 * a refusal leaves nothing behind.
 */
export async function assertInvitationsPossible(
	bucket: UserBucket
): Promise<void> {
	if (!bucket.passwordLogin) {
		throw new EndUserError(
			409,
			'this project does not sign people in with a password'
		);
	}
	if (!(await mailDeliveryConfigured())) {
		throw new EndUserError(409, 'mail delivery is not configured');
	}
}

/*
 * Mails a person a link to set their own password (specs/089), so no administrator invents one and hands it
 * over. Refused for a directory's person — the directory owns their credentials and address — and for one who
 * cannot sign in, before the entry; a send the throttle would refuse is answered as such, also before it.
 */
export async function inviteEndUser(
	bucket: UserBucket,
	actor: EndUserActor,
	id: string,
	record: RecordChange
): Promise<InviteOutcome> {
	const user = await existing(bucket._id, id);
	assertActorMayChange(actor, user);
	await assertInvitationsPossible(bucket);
	if (!canSignIn(user)) {
		throw new EndUserError(409, 'this person cannot sign in');
	}
	const retryAfter = await inviteRetryAfter(user, bucket);
	if (retryAfter !== null) return { outcome: 'rate_limited', retryAfter };
	await record();
	return invite(user, bucket);
}

/*
 * An administrator's statement that the person controls their address, made after confirming it some other
 * way (specs/089). A named act rather than a field of the update: the update never lets an administrator
 * assert verification. Refused for a directory's person, whose address trust is the connection's setting, and
 * a no-op refusal when nothing would change, so the trail records only marks that moved something. A pending
 * verification message stops working with it.
 */
export async function markEndUserVerified(
	bucket: UserBucket,
	actor: EndUserActor,
	id: string,
	record: RecordChange
): Promise<User> {
	const user = await existing(bucket._id, id);
	assertActorMayChange(actor, user);
	if (user.verified) throw new EndUserError(409, 'already verified');
	await record();
	const marked = await getUserStore(bucket._id).update(id, { verified: true });
	if (!marked) throw new EndUserError(404, 'user not found');
	await discardPending(bucket._id, user);
	return marked;
}

/*
 * Signs a person out of one application and leaves the others alone (specs/089): what the end-session
 * endpoint's partial sign-out does for one session, done for every session of theirs in this bucket, and
 * further — the application's grants go with every token under them, offline ones included, because "sign
 * out of this app" that left a refresh token working would sign out nothing.
 *
 * Allowed on a directory's person, as signing out everywhere is: it ends access and edits nothing the
 * directory owns.
 */
export async function endApplicationAccess(
	bucket: UserBucket,
	id: string,
	clientId: string,
	record: RecordChange
): Promise<void> {
	await existing(bucket._id, id);
	const sessions = (await sessionsIn(bucket._id, id)).filter((session) =>
		Object.hasOwn(session.payload.authorizations ?? {}, clientId)
	);
	const grants = (await grantsIn(bucket._id, id)).filter(
		(grant) => grant.payload.clientId === clientId
	);
	if (sessions.length === 0 && grants.length === 0) {
		throw new EndUserError(
			404,
			'the person is not signed in to this application'
		);
	}
	await record();

	const grantIds = new Set(grants.map((grant) => grant.id));
	for (const session of sessions) {
		/* Told while the session still names the sign-in: the logout token carries its `sid`. */
		if (ApplicationConfig['backchannelLogout.enabled']) {
			await backchannelLogoutFor(session, [clientId]);
		}
		const authorizations = session.payload.authorizations ?? {};
		/* Present: only sessions holding this client's entry were kept above. */
		const { grantId } = authorizations[clientId];
		if (grantId !== undefined) grantIds.add(grantId);
		delete authorizations[clientId];
		/*
		 * Saved with what was left of its life. A save renews the full lifetime by default, so the person's
		 * other sign-ins would outlast what they signed in for because an administrator ended one of them.
		 */
		const remaining = (session.payload.exp ?? 0) - epochTime();
		if (remaining > 0) await session.save(remaining);
	}

	await endGrants(grantIds);
}

/*
 * The person's own choice of language, saved when they finish a sign-in after using the language switch
 * (specs/097), so the next email and the next sign-in come in it. The browser's language is never saved — only
 * this explicit choice is.
 *
 * Not an administrative change, so no audit record: nobody's access changes, and the trail is for what
 * administrators do. A directory-provisioned person is left alone, because the directory owns `locale` and its
 * next sync would put its own value back. A stored `ru-RU` that already means Russian is kept as it is.
 */
export async function recordOwnLanguage(
	bucketId: string,
	accountId: string,
	language: Language
): Promise<void> {
	const store = getUserStore(bucketId);
	const user = await store.find(accountId);
	if (!user || user.provisionedBy) return;
	if (lookup(storedLocaleRanges(user)) === language) return;
	await store.update(accountId, {
		profile: { ...user.profile, locale: language }
	});
}
