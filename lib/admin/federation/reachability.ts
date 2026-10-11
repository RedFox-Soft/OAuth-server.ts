import { getBucketStore, getUserStore } from '../../adapters/index.js';
import type { User } from '../../adapters/types.js';
import { canSignIn } from '../../end_users/can_sign_in.js';
import { domainAllowed } from '../../federation/domains.js';
import type { FederationProvider } from '../../federation/types.js';
import { AdminError } from '../auth/rbac.js';
import { ADMIN_BUCKET_ID } from '../consts.js';
import { superAdminIds } from '../super_admins.js';

/*
 * Whether the console can still be reached once password sign-in to it is off (specs/080).
 *
 * With passwords on, every administrator has a door. With them off, the console is reachable only while some
 * active super administrator is linked at an enabled provider of the administrators' bucket that still admits
 * their address: a super administrator, because only one can turn passwords back on from the console, and
 * "still admits", because narrowing a provider's domains shuts a linked account out as surely as disabling it.
 *
 * One predicate, asked by every change that can break it — turning passwords off, disabling, narrowing or
 * deleting a provider, deactivating or deleting an administrator, withdrawing the privilege — so the entry
 * points cannot disagree about what "locked out" means. Each caller applies its change to a loaded state and
 * asks about the result, rather than each re-deriving the rule from its own corner.
 */

export interface ReachabilityState {
	passwordLogin: boolean;
	providers: readonly FederationProvider[];
	superAdministrators: readonly User[];
}

export async function loadReachabilityState(): Promise<ReachabilityState> {
	const bucket = await getBucketStore().find(ADMIN_BUCKET_ID);
	if (!bucket) throw new AdminError(500, 'the admin bucket is missing');
	const users = getUserStore(ADMIN_BUCKET_ID);
	const superAdministrators = (
		await Promise.all((await superAdminIds()).map((id) => users.find(id)))
	).filter((user): user is User => user !== null);
	return {
		passwordLogin: bucket.passwordLogin,
		providers: bucket.federation,
		superAdministrators
	};
}

/* The super administrators who could sign in through a provider right now. */
export function reachableSuperAdministrators(state: ReachabilityState): User[] {
	return state.superAdministrators.filter(
		(user) => canSignIn(user) && reachableThroughProvider(user, state.providers)
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
	throw new AdminError(
		409,
		`${what} would leave no super administrator able to sign in to the console: password sign-in is off, and no other active super administrator is linked at an enabled identity provider of the Administrators bucket. Link one first, or turn password sign-in back on.`
	);
}
