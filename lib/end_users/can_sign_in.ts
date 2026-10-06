import type { User } from '../adapters/types.js';

/*
 * Whether this account may sign in or be issued anything. One predicate for every place that asks — account
 * resolution and both sign-in doors — because two copies of "is this user allowed" drift, and the drifted copy
 * is the door a locked user walks through.
 *
 * `active` belongs to whoever manages the user (an administrator, or a provisioning connection); the local lock
 * belongs only to an administrator. Either one alone refuses.
 */
export function canSignIn(
	user: Pick<User, 'active' | 'lockedLocally'>
): boolean {
	return user.active && !user.lockedLocally;
}
