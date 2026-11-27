import {
	getBucketStore,
	getPasskeyStore,
	getUserStore
} from '../../adapters/index.js';
import type { User } from '../../adapters/types.js';
import { canSignIn } from '../../end_users/can_sign_in.js';
import { domainAllowed } from '../../federation/domains.js';
import type { FederationProvider } from '../../federation/types.js';
import { rpIdFor } from '../../passkeys/relying_party.js';
import { AdminError } from '../auth/rbac.js';
import { ADMIN_BUCKET_ID } from '../consts.js';
import { superAdminIds } from '../super_admins.js';

/*
 * Whether the console can still be reached once a sign-in change is applied (specs/080, specs/144).
 *
 * When `consolePasskeyRequired` is on, only a working passkey of an active super administrator reaches the console —
 * neither password sign-in nor an identity provider satisfies it — so `passkeyLogin` must stay on and at least one
 * active super administrator must hold a working passkey (current root RP ID, not marked copied, not conditional).
 *
 * When `consolePasskeyRequired` is off, passwords on keeps every administrator a door; with them off, the console is
 * reachable while some active super administrator is either linked at an enabled provider of the administrators' bucket
 * that still admits their address, or holds a working passkey while `passkeyLogin` is on.
 *
 * One predicate, asked by every change that can break it — turning passwords or passkeys off, turning the console
 * passkey requirement on, disabling, narrowing or deleting a provider, deactivating or deleting an administrator,
 * withdrawing the privilege, or removing/revoking/disowning a super administrator's passkey — so the entry points
 * cannot disagree about what "locked out" means.
 */

export interface ReachabilityState {
	passwordLogin: boolean;
	passkeyLogin: boolean;
	consolePasskeyRequired: boolean;
	providers: readonly FederationProvider[];
	superAdministrators: readonly User[];
	/* Active working passkey counts (current root RP ID, not copied, not conditional) per super administrator id. */
	superAdminPasskeyCounts: ReadonlyMap<string, number>;
}

export async function loadReachabilityState(): Promise<ReachabilityState> {
	const bucket = await getBucketStore().find(ADMIN_BUCKET_ID);
	if (!bucket)
		throw new AdminError(500, "the administrators' project is missing");
	const users = getUserStore(ADMIN_BUCKET_ID);
	const superAdministrators = (
		await Promise.all((await superAdminIds()).map((id) => users.find(id)))
	).filter((user): user is User => user !== null);
	const rpId = rpIdFor(bucket);
	const passkeyStore = getPasskeyStore();
	const counts = new Map<string, number>();
	await Promise.all(
		superAdministrators.map(async (user) => {
			const held = await passkeyStore.listOf(ADMIN_BUCKET_ID, user._id);
			const working = held.filter(
				(passkey) =>
					passkey.rpId === rpId &&
					passkey.copiedAt === undefined &&
					passkey.conditional !== true
			).length;
			counts.set(user._id, working);
		})
	);
	return {
		passwordLogin: bucket.passwordLogin,
		passkeyLogin: bucket.passkeyLogin === true,
		consolePasskeyRequired: bucket.consolePasskeyRequired === true,
		providers: bucket.federation,
		superAdministrators,
		superAdminPasskeyCounts: counts
	};
}

export function hasWorkingPasskey(
	userId: string,
	state: Pick<ReachabilityState, 'superAdminPasskeyCounts'>
): boolean {
	return (state.superAdminPasskeyCounts.get(userId) ?? 0) > 0;
}

/* The super administrators who could sign in through a provider right now. */
export function reachableThroughProvidersSuperAdministrators(
	state: ReachabilityState
): User[] {
	return state.superAdministrators.filter(
		(user) => canSignIn(user) && reachableThroughProvider(user, state.providers)
	);
}

/* The super administrators who could sign in with a passkey right now (when passkeys are on). */
export function reachablePasskeySuperAdministrators(
	state: ReachabilityState
): User[] {
	if (!state.passkeyLogin) return [];
	return state.superAdministrators.filter(
		(user) => canSignIn(user) && hasWorkingPasskey(user._id, state)
	);
}

/* The super administrators who could sign in to the console without a password right now. */
export function reachableSuperAdministrators(state: ReachabilityState): User[] {
	if (state.consolePasskeyRequired) {
		return reachablePasskeySuperAdministrators(state);
	}
	return state.superAdministrators.filter(
		(user) =>
			canSignIn(user) &&
			(reachableThroughProvider(user, state.providers) ||
				(state.passkeyLogin && hasWorkingPasskey(user._id, state)))
	);
}

/* Whether this account could sign in through one of the enabled providers. */
export function reachableThroughProvider(
	user: User,
	providers: readonly FederationProvider[]
): boolean {
	return (user.federated ?? []).some((link) =>
		providers.some(
			(provider) =>
				provider.enabled &&
				provider.id === link.providerId &&
				domainAllowed(user.email, provider)
		)
	);
}

export function consoleStaysReachable(state: ReachabilityState): boolean {
	if (state.consolePasskeyRequired) {
		return reachablePasskeySuperAdministrators(state).length > 0;
	}
	return state.passwordLogin || reachableSuperAdministrators(state).length > 0;
}

/*
 * Refuses a change whose result would shut every administrator out of the console. `what` names the change
 * in the refusal, so the operator reads why this particular act was refused.
 */
export function assertConsoleStaysReachable(
	after: ReachabilityState,
	what: string
): void {
	if (consoleStaysReachable(after)) return;
	if (after.consolePasskeyRequired) {
		throw new AdminError(
			409,
			`${what} would leave no super administrator able to sign in to the console: console sign-in requires a passkey, and no other active super administrator holds a working passkey. Add another super administrator's passkey first, or turn off the console passkey requirement.`
		);
	}
	throw new AdminError(
		409,
		`${what} would leave no super administrator able to sign in to the console: password sign-in is off, and no other active super administrator can sign in through an enabled identity provider or a passkey. Add another way in first, or turn password sign-in back on.`
	);
}
