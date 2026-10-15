import {
	getProvisioningConnectionStore,
	getUserStore
} from '../adapters/index.js';
import type {
	ProvisioningConnection,
	User,
	UserBucket
} from '../adapters/types.js';
import { eventBus } from '../event_bus.js';
import { unusablePassword } from '../helpers/unusable_password.js';
import { canSignIn } from '../end_users/can_sign_in.js';
import { COPIED_CLAIMS } from './consts.js';
import type {
	FederationProvider,
	PendingLinkIdentity,
	RefusalReason
} from './types.js';
import { domainAllowed } from './domains.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import { signUpsPaused } from '../plans/signups.js';

/*
 * Turn a verified assertion into a signed-in account, or into a refusal.
 *
 * The order of the steps is the contract, not a preference — see
 * specs/022-oidc-federation-login/contracts/sign-in-decision.md. Two orderings in particular are
 * load-bearing: the existing link is consulted before the email (the link *is* the identity; the email is
 * only how one is established), and the domain check precedes the collision check (reversed, it would
 * answer "does an account exist for this address?" for addresses the provider is not allowed to speak for).
 */

/* Declared beside the try's stored result, which records one (./types.ts). */
export type { RefusalReason };

export type Resolution =
	| { ok: true; account: User; provisioned: boolean }
	| { ok: false; reason: RefusalReason }
	/*
	 * The address belongs to an account whose password somebody set without proving the address, so the
	 * assertion may not claim it on its own. Nobody is signed in; the identity waits for that account's
	 * own sign-in to complete.
	 */
	| {
			ok: false;
			reason: 'password_required';
			account: User;
			link: PendingLinkIdentity;
	  };

function emailFrom(
	claims: Record<string, unknown>,
	provider: FederationProvider
): string | undefined {
	const value = claims[provider.emailClaim];
	if (typeof value !== 'string') return undefined;
	const trimmed = value.trim();
	return trimmed.length > 0 ? trimmed : undefined;
}

/*
 * The trust boundary, and both halves are required: the operator trusts this provider's addresses, **and**
 * this particular assertion says the address is verified. `=== true` exactly — not truthy, so neither the
 * string "true" nor a stray 1 can stand in for a provider's claim.
 */
function trustedVerified(
	claims: Record<string, unknown>,
	provider: FederationProvider
): boolean {
	return provider.emailTrusted && claims.email_verified === true;
}

function copiedClaims(
	claims: Record<string, unknown>
): Record<string, unknown> | undefined {
	const copied: Record<string, unknown> = {};
	for (const name of COPIED_CLAIMS) {
		if (claims[name] !== undefined) copied[name] = claims[name];
	}
	return Object.keys(copied).length > 0 ? copied : undefined;
}

/*
 * Attach an upstream identity to an account. `profile` is copied when a link is established, never on a
 * later sign-in through it: a provider should not silently rewrite a user's name on every login, and an
 * operator's edit should survive.
 *
 * Uniqueness of (providerId, sub) is enforced by the callers rather than by a unique index, which cannot
 * be expressed for a multikey field the inventory can model: each has just proved the pair resolves to
 * nobody, so a second holder can only appear through a concurrent double-link — whose outcome is a
 * duplicate entry naming this same account, not a shared identity.
 */
export async function linkIdentity(
	store: ReturnType<typeof getUserStore>,
	account: User,
	identity: PendingLinkIdentity
): Promise<User | null> {
	const federated = [
		...(account.federated ?? []),
		{ providerId: identity.providerId, sub: identity.sub, linkedAt: new Date() }
	];
	const profile = identity.claims;
	return store.update(account._id, {
		federated,
		...(profile ? { claims: { ...account.claims, ...profile } } : {})
	});
}

async function connectionForProvider(
	bucketId: string,
	providerId: string
): Promise<ProvisioningConnection | null> {
	return getProvisioningConnectionStore().findByProvider(bucketId, providerId);
}

/*
 * What the ladder decided, before anything is written (specs/088 R5). The ladder is split in two so a try
 * of a provider can run the very rules a sign-in runs and stop here, with nothing written — a copy of the
 * ladder for the try would drift from the real one, and this cannot.
 *
 * Two outcomes exist only after a write and are therefore not decisions: `link_not_permitted` when the
 * link write finds nothing to update, and `inactive` after linking or creating. `applyDecision` checks
 * both; they guard races, and a try reports the decision that preceded them.
 */
export type Decision =
	| { kind: 'signin'; account: User }
	/* `account` is the one the refusal is about, where there is one — a try names it, a sign-in does not. */
	| { kind: 'refuse'; reason: RefusalReason; account?: User }
	/* The correlated account is already linked to another subject at this provider. */
	| { kind: 'conflict'; account: User; connectionId: string }
	| {
			kind: 'link';
			account: User;
			identity: PendingLinkIdentity;
			via: 'email' | 'correlation';
			/* The provisioning connection that named the account, for a link via correlation. */
			connectionId?: string;
	  }
	| { kind: 'password_required'; account: User; link: PendingLinkIdentity }
	| {
			kind: 'provision';
			email: string;
			verified: boolean;
			profile?: Record<string, unknown>;
			subject: string;
	  };

export interface ResolutionInput {
	bucket: UserBucket;
	provider: FederationProvider;
	subject: string;
	claims: Record<string, unknown>;
}

async function decideCorrelated(
	store: ReturnType<typeof getUserStore>,
	provider: FederationProvider,
	connection: ProvisioningConnection,
	subject: string,
	claims: Record<string, unknown>
): Promise<Decision> {
	const value = claims[connection.correlation.claim];
	if (typeof value !== 'string' || value.trim() === '') {
		return { kind: 'refuse', reason: 'not_provisioned' };
	}
	const filter =
		connection.correlation.attribute === 'externalId'
			? { provisionedBy: connection._id, externalId: value }
			: { provisionedBy: connection._id, userName: value };
	const { users } = await store.query(filter, { startIndex: 1, count: 2 });
	/* Both keys are unique per connection, so more than one match is a defect; refuse rather than guess. */
	if (users.length !== 1) return { kind: 'refuse', reason: 'not_provisioned' };
	const [account] = users;

	if (account.federated?.some((link) => link.providerId === provider.id)) {
		return { kind: 'conflict', account, connectionId: connection._id };
	}
	/*
	 * Linked without copying the upstream's profile claims: a provisioned user's profile belongs to the
	 * directory, which keeps it current over SCIM.
	 */
	return {
		kind: 'link',
		account,
		identity: { providerId: provider.id, sub: subject },
		via: 'correlation',
		connectionId: connection._id
	};
}

/* Reads only. Every write the ladder makes is in `applyDecision`. */
export async function decideFederatedAccount(
	input: ResolutionInput
): Promise<Decision> {
	const { bucket, provider, subject, claims } = input;
	const store = getUserStore(bucket._id);

	// 1. An existing link is the identity. Nothing else is consulted, and nothing is written.
	const linked = await store.findByFederatedIdentity(provider.id, subject);
	if (linked) {
		/* `canSignIn`, not `active`: a locally locked account is refused here, not only at the door after. */
		return canSignIn(linked)
			? { kind: 'signin', account: linked }
			: { kind: 'refuse', reason: 'inactive', account: linked };
	}

	/*
	 * 1a. A provider bound to a SCIM provisioning connection ends the ladder here (specs/070 R14). The
	 * directory created the account; the connection's correlation rule names which one, by a claim the
	 * directory also sent over SCIM (Entra's `oid` as `externalId`). The email steps below are never reached:
	 * matching by address is the takeover the series refuses, and a provisioned account holding no password
	 * would otherwise be sent to a password step it can never complete.
	 */
	const connection = await connectionForProvider(bucket._id, provider.id);
	if (connection) {
		return decideCorrelated(store, provider, connection, subject, claims);
	}

	// 2. No address means nothing to match a human by.
	const email = emailFrom(claims, provider);
	if (!email) {
		return { kind: 'refuse', reason: 'no_email' };
	}

	// 3. Before any lookup, so a disallowed domain cannot probe for existing accounts.
	if (!domainAllowed(email, provider)) {
		return { kind: 'refuse', reason: 'domain_not_allowed' };
	}

	const existing = await store.findByEmail(email);

	// 4. The takeover boundary.
	if (existing) {
		if (!trustedVerified(claims, provider)) {
			return {
				kind: 'refuse',
				reason: 'link_not_permitted',
				account: existing
			};
		}
		if (!canSignIn(existing)) {
			return { kind: 'refuse', reason: 'inactive', account: existing };
		}
		const identity: PendingLinkIdentity = {
			providerId: provider.id,
			sub: subject,
			claims: copiedClaims(claims)
		};
		/*
		 * The assertion proves who controls the address; it proves nothing about whoever set this account's
		 * password, and in a bucket that does not verify addresses anybody can register one. An account that
		 * already holds an upstream identity had its address established by a trusted assertion, so it links
		 * as before. One holding only a password links once its own sign-in completes — otherwise
		 * registering a victim's address first turned their federated sign-in into access for whoever did.
		 *
		 * A bucket with no password door is the exception: there is no sign-in to prove the account with,
		 * and nobody can have registered one there with a password.
		 *
		 * The console's own bucket has no exceptions (specs/080): every new link to an administrator needs
		 * the password proof, whichever provider and whatever the account already holds. There the account
		 * behind the address may be a super administrator, and without the proof any provider trusted for
		 * the address — a second one, or any one once passwords are off — would sign its holder in as them.
		 * With passwords off no new link can be made at all, which the console says before they go off.
		 */
		const inConsole = bucket._id === ADMIN_BUCKET_ID;
		if (inConsole || (bucket.passwordLogin && !existing.federated?.length)) {
			return { kind: 'password_required', account: existing, link: identity };
		}
		// Step 1 already proved this pair resolves to nobody.
		return { kind: 'link', account: existing, identity, via: 'email' };
	}

	/*
	 * 5. No account: the provider's own knob decides, not the bucket's password-registration setting — except
	 * for the console's own bucket, where a closed sign-up closes every way to become an administrator
	 * (specs/080, research question 9.4).
	 */
	if (bucket._id === ADMIN_BUCKET_ID && !bucket.registrationOpen) {
		return { kind: 'refuse', reason: 'provisioning_closed' };
	}
	if (provider.provisioning === 'existing_only') {
		return { kind: 'refuse', reason: 'provisioning_closed' };
	}
	/* The project's plan has reached its monthly active users (specs/102): no new account, every sign-in still. */
	if (await signUpsPaused(bucket)) {
		return { kind: 'refuse', reason: 'signups_paused' };
	}

	const profile = copiedClaims(claims);
	return {
		kind: 'provision',
		email,
		// Verified by the same test that governs linking, so a provisioned account is never more trusted
		// than the assertion that created it.
		verified: trustedVerified(claims, provider),
		...(profile ? { profile } : {}),
		subject
	};
}

/* Every write the ladder makes, and the checks that can only follow a write. */
export async function applyDecision(
	input: Pick<ResolutionInput, 'bucket' | 'provider'>,
	decision: Decision
): Promise<Resolution> {
	const { bucket, provider } = input;
	const store = getUserStore(bucket._id);

	switch (decision.kind) {
		case 'signin':
			return { ok: true, account: decision.account, provisioned: false };
		case 'refuse':
			return { ok: false, reason: decision.reason };
		case 'conflict':
			eventBus.emit('federation.link.conflict', {
				providerId: provider.id,
				connectionId: decision.connectionId
			});
			return { ok: false, reason: 'link_conflict' };
		case 'password_required':
			return {
				ok: false,
				reason: 'password_required',
				account: decision.account,
				link: decision.link
			};
		case 'link': {
			const updated = await linkIdentity(
				store,
				decision.account,
				decision.identity
			);
			if (decision.via === 'correlation') {
				const account = updated ?? decision.account;
				return canSignIn(account)
					? { ok: true, account, provisioned: false }
					: { ok: false, reason: 'inactive' };
			}
			return updated
				? { ok: true, account: updated, provisioned: false }
				: { ok: false, reason: 'link_not_permitted' };
		}
		case 'provision': {
			const created = await store.create(
				decision.email,
				await unusablePassword(),
				decision.verified,
				undefined,
				// Said rather than left absent, so an administrator is told no password opens this account.
				{ passwordSet: false }
			);
			const completed = await store.update(created._id, {
				federated: [
					{
						providerId: provider.id,
						sub: decision.subject,
						linkedAt: new Date()
					}
				],
				...(decision.profile ? { claims: decision.profile } : {})
			});

			const account = completed ?? created;
			// 6. Written as the rule rather than skipped as impossible, so it stays right if provisioning ever
			// gains a default that is not active.
			if (!canSignIn(account)) {
				return { ok: false, reason: 'inactive' };
			}
			return { ok: true, account, provisioned: true };
		}
	}
}

/* A real sign-in: the decision, then its application — exactly what it was before the ladder was split. */
export async function resolveFederatedAccount(
	input: ResolutionInput
): Promise<Resolution> {
	return applyDecision(input, await decideFederatedAccount(input));
}
