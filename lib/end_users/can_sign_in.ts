/*
 * Whether this account may sign in or be issued anything. One predicate for every place that asks — account
 * resolution and both sign-in doors — because two copies of "is this user allowed" drift, and the drifted copy
 * is the door a locked user walks through.
 *
 * `active` belongs to whoever manages the user (an administrator, or a provisioning connection); the local lock
 * belongs only to an administrator. Either one alone refuses.
 *
 * Typed by the two facts it reads rather than by the stored record, so the console's access check (specs/122) can
 * ask it about a person as the admin routes answer them: there, a lock's dates are strings.
 */
export function canSignIn(user: {
	active: boolean;
	lockedLocally?: unknown;
}): boolean {
	return user.active && !user.lockedLocally;
}
