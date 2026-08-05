import crypto from 'crypto';

import { getUserStore } from '../adapters/index.js';
import type { User, UserBucket } from '../adapters/types.js';
import { COPIED_CLAIMS } from './consts.js';
import type { FederationProvider } from './types.js';

/*
 * Turn a verified assertion into a signed-in account, or into a refusal.
 *
 * The order of the steps is the contract, not a preference — see
 * specs/022-oidc-federation-login/contracts/sign-in-decision.md. Two orderings in particular are
 * load-bearing: the existing link is consulted before the email (the link *is* the identity; the email is
 * only how one is established), and the domain check precedes the collision check (reversed, it would
 * answer "does an account exist for this address?" for addresses the provider is not allowed to speak for).
 */

export type RefusalReason =
	/* The assertion carries no address, so nothing can be linked or provisioned. */
	| 'no_email'
	/* The address is outside a non-empty allow-list. */
	| 'domain_not_allowed'
	/* An account holds this address, but this provider may not claim it. */
	| 'link_not_permitted'
	/* No account, and this provider does not provision. */
	| 'provisioning_closed'
	/* Whichever branch produced it, the account is frozen. */
	| 'inactive';

export type Resolution =
	| { ok: true; account: User; provisioned: boolean }
	| { ok: false; reason: RefusalReason };

/*
 * A password no one can type. The hash is of 32 random bytes discarded on the next line — deliberately not
 * a sentinel string, which would be a value someone could eventually guess, submit, or find in this source.
 * A federated account acquires a usable password only through the self-service reset.
 */
async function unusablePassword(): Promise<string> {
	return Bun.password.hash(crypto.randomBytes(32).toString('base64url'));
}

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
 * Case-insensitive on the domain part, against entries stored as bare lowercase domains. No subdomain
 * wildcarding: `acme.com` does not admit `eu.acme.com`, and — the case that matters — a suffix comparison
 * would have admitted `acme.com.evil.test`.
 */
function domainAllowed(email: string, provider: FederationProvider): boolean {
	if (provider.allowedEmailDomains.length === 0) return true;
	const at = email.lastIndexOf('@');
	if (at === -1) return false;
	const domain = email.slice(at + 1).toLowerCase();
	return provider.allowedEmailDomains.includes(domain);
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

export async function resolveFederatedAccount(input: {
	bucket: UserBucket;
	provider: FederationProvider;
	subject: string;
	claims: Record<string, unknown>;
}): Promise<Resolution> {
	const { bucket, provider, subject, claims } = input;
	const store = getUserStore(bucket._id);

	// 1. An existing link is the identity. Nothing else is consulted, and nothing is written.
	const linked = await store.findByFederatedIdentity(provider.id, subject);
	if (linked) {
		return linked.active
			? { ok: true, account: linked, provisioned: false }
			: { ok: false, reason: 'inactive' };
	}

	// 2. No address means nothing to match a human by.
	const email = emailFrom(claims, provider);
	if (!email) {
		return { ok: false, reason: 'no_email' };
	}

	// 3. Before any lookup, so a disallowed domain cannot probe for existing accounts.
	if (!domainAllowed(email, provider)) {
		return { ok: false, reason: 'domain_not_allowed' };
	}

	const existing = await store.findByEmail(email);

	// 4. The takeover boundary.
	if (existing) {
		if (!trustedVerified(claims, provider)) {
			return { ok: false, reason: 'link_not_permitted' };
		}
		if (!existing.active) {
			return { ok: false, reason: 'inactive' };
		}
		/*
		 * Uniqueness of (providerId, sub) is enforced here rather than by a unique index, which cannot be
		 * expressed for a multikey field the inventory can model. Step 1 already proved this pair resolves to
		 * nobody, so a second holder can only appear through a concurrent double-link — whose outcome is a
		 * duplicate entry naming this same account, not a shared identity.
		 */
		const federated = [
			...(existing.federated ?? []),
			{ providerId: provider.id, sub: subject, linkedAt: new Date() }
		];
		const profile = copiedClaims(claims);
		const updated = await store.update(existing._id, {
			federated,
			// Copied when a link is established, never on a later sign-in through it: an provider should not
			// silently rewrite a user's name on every login, and an operator's edit should survive.
			...(profile ? { claims: { ...existing.claims, ...profile } } : {})
		});
		return updated
			? { ok: true, account: updated, provisioned: false }
			: { ok: false, reason: 'link_not_permitted' };
	}

	// 5. No account: the provider's own knob decides, not the bucket's password-registration setting.
	if (provider.provisioning === 'existing_only') {
		return { ok: false, reason: 'provisioning_closed' };
	}

	const created = await store.create(
		email,
		await unusablePassword(),
		[],
		// Verified by the same test that governs linking, so a provisioned account is never more trusted
		// than the assertion that created it.
		trustedVerified(claims, provider)
	);
	const profile = copiedClaims(claims);
	const completed = await store.update(created._id, {
		federated: [
			{ providerId: provider.id, sub: subject, linkedAt: new Date() }
		],
		...(profile ? { claims: profile } : {})
	});

	const account = completed ?? created;
	// 6. Written as the rule rather than skipped as impossible, so it stays right if provisioning ever
	// gains a default that is not active.
	if (!account.active) {
		return { ok: false, reason: 'inactive' };
	}
	return { ok: true, account, provisioned: true };
}
