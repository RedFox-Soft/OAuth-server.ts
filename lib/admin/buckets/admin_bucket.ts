import { getPasskeyStore, getUserStore } from '../../adapters/index.js';
import type { UserBucket } from '../../adapters/types.js';
import { meets } from '../../helpers/acr_satisfaction.ts';
import { rpIdFor } from '../../passkeys/relying_party.js';
import { AdminError, type AdminContext } from '../auth/rbac.js';
import { ADMIN_BUCKET_ID } from '../consts.js';
import {
	assertConsoleStaysReachable,
	loadReachabilityState
} from '../federation/reachability.js';

/*
 * The administrators' bucket is configured through the same settings as every bucket; what differs is that
 * a careless setting here shuts the console, and with it the only surface that could undo the setting. Each
 * such setting carries its own guard instead of the blanket refusal this bucket used to get.
 *
 * Turning password sign-in off is allowed only to someone who has just come in through one of this bucket's
 * providers (specs/080): the console session records the provider it signed in through, and the account must
 * be linked there. Whoever turns the door off has proven, in that very session, that another one works. And
 * the result must leave some super administrator a way in (lib/admin/federation/reachability.ts), so passwords
 * cannot go off while every remaining door leads nowhere. An agent has no console session and never qualifies.
 *
 * Turning the console passkey requirement on (specs/144) follows the same self-proof principle: passkeys must
 * be on (already or in the same change), and the acting super administrator must hold a working passkey and
 * have authenticated the current session (or authorizing agent grant) with a passkey — proving a passkey works
 * before passwords and providers stop reaching the console. Turning passkeys off is refused while the console
 * passkey requirement remains on, or whenever it would leave no super administrator able to reach the console.
 *
 * Requiring verification is the one that needed a guard of its own. It refuses every unverified
 * administrator at the door, so it may be turned on only when the message can actually be sent — the route
 * refuses that on every bucket (specs/083) — and only by someone the requirement cannot lock out: the person
 * changing it must already have proven their own address, so the requirement can never refuse the one
 * administrator who set it.
 */
export async function assertAdminBucketChange(
	ctx: AdminContext,
	bucket: UserBucket,
	patch: {
		emailVerificationRequired?: boolean;
		passwordLogin?: boolean;
		registrationOpen?: boolean;
		passkeyLogin?: boolean;
		consolePasskeyRequired?: boolean;
	}
): Promise<void> {
	assertSignUpNeedsVerification({ ...bucket, ...patch });
	const passkeysAfter = patch.passkeyLogin ?? bucket.passkeyLogin === true;
	const requirePasskeyAfter =
		patch.consolePasskeyRequired ?? bucket.consolePasskeyRequired === true;

	if (
		patch.consolePasskeyRequired === true &&
		bucket.consolePasskeyRequired !== true
	) {
		if (!passkeysAfter) {
			throw new AdminError(
				409,
				'Turn on Passkeys for administrators before requiring a passkey to sign in to the console.',
				{ code: 'passkeys_not_accepted', field: 'consolePasskeyRequired' }
			);
		}
		await assertMayRequireConsolePasskey(ctx, bucket);
	}

	if (patch.passkeyLogin === false && bucket.passkeyLogin === true) {
		if (requirePasskeyAfter) {
			throw new AdminError(
				409,
				'Turn off the console passkey requirement first, or in the same change, before turning passkeys off.',
				{ field: 'passkeyLogin' }
			);
		}
		const state = await loadReachabilityState();
		assertConsoleStaysReachable(
			{
				...state,
				passwordLogin: patch.passwordLogin ?? state.passwordLogin,
				passkeyLogin: false,
				consolePasskeyRequired: false
			},
			'Turning passkeys off'
		);
	}

	if (patch.passwordLogin === false && bucket.passwordLogin) {
		await assertMayTurnPasswordsOff(ctx, bucket, {
			passkeyLogin: passkeysAfter,
			consolePasskeyRequired: requirePasskeyAfter
		});
	}
	if (patch.emailVerificationRequired !== true) return;
	const acting = await getUserStore(ADMIN_BUCKET_ID).find(ctx.userId);
	if (!acting?.verified) {
		throw new AdminError(
			409,
			'verify your own address before requiring verification of administrators'
		);
	}
}

async function assertMayRequireConsolePasskey(
	ctx: AdminContext,
	bucket: UserBucket
): Promise<void> {
	const rpId = rpIdFor(bucket);
	const held = await getPasskeyStore().listOf(ADMIN_BUCKET_ID, ctx.userId);
	const hasWorking = held.some(
		(passkey) =>
			passkey.rpId === rpId &&
			passkey.copiedAt === undefined &&
			passkey.conditional !== true
	);
	if (!hasWorking) {
		throw new AdminError(
			409,
			'Add a passkey to your own account first, then sign in with it before requiring a passkey for console sign-in.'
		);
	}
	if (!meets(ctx.signInAcr, 'phishing_resistant')) {
		throw new AdminError(
			409,
			'Sign in with a passkey first, then require a passkey for console sign-in.'
		);
	}
	const state = await loadReachabilityState();
	assertConsoleStaysReachable(
		{ ...state, passkeyLogin: true, consolePasskeyRequired: true },
		'Requiring a passkey for console sign-in'
	);
}

/*
 * Sign-up open means verification required, judged on the state the change would leave (specs/103).
 *
 * This used to be said rather than refused — an open console with no proof of address was taken to be a choice
 * for an instance behind its own network. It is not one: anyone could register under a colleague's address, and
 * the colleague's next team invitation joined that account to the team, as an owner if that was the invitation.
 * A closed network narrows who can register; it does not make the address theirs. With proof required, such an
 * account cannot sign in, and accepting the invitation hands it to whoever holds the mailbox
 * (lib/admin/groups/accept.ts).
 */
function assertSignUpNeedsVerification(
	state: Pick<UserBucket, 'registrationOpen' | 'emailVerificationRequired'>
): void {
	if (state.registrationOpen && !state.emailVerificationRequired) {
		throw new AdminError(
			409,
			'administrators can sign up only with email verification on: turn verification on in the same change'
		);
	}
}

async function assertMayTurnPasswordsOff(
	ctx: AdminContext,
	bucket: UserBucket,
	after: { passkeyLogin: boolean; consolePasskeyRequired: boolean }
): Promise<void> {
	const provider = bucket.federation.find(
		(p) => p.id === ctx.signedInWith && p.enabled
	);
	const acting = await getUserStore(ADMIN_BUCKET_ID).find(ctx.userId);
	const linked = (acting?.federated ?? []).some(
		(link) => link.providerId === provider?.id
	);
	if (!provider || !linked) {
		throw new AdminError(
			409,
			"Sign in through one of this project's identity providers first, then turn password sign-in off."
		);
	}
	const state = await loadReachabilityState();
	assertConsoleStaysReachable(
		{
			...state,
			passwordLogin: false,
			passkeyLogin: after.passkeyLogin,
			consolePasskeyRequired: after.consolePasskeyRequired
		},
		'Turning password sign-in off'
	);
}
