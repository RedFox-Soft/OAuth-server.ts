import type { User } from '../../../../adapters/types.js';

/*
 * What the API actually returns, which is not the stored record: `presentUser` removes the password
 * hash and the authenticator secret, and substitutes the two derived facts an operator may see. Typed
 * from that shape rather than from `User` so the console cannot accidentally reference a field the
 * server does not send.
 */
export type EndUser = Omit<
	User,
	| 'password'
	| 'totp'
	| 'lockedLocally'
	| 'createdAt'
	| 'updatedAt'
	| 'lastLoginAt'
	| 'userNameKey'
	| 'externalIdKey'
> & {
	createdAt: string;
	totpEnrolled: boolean;
	totpEnrolledAt: string | null;
	groups?: { id: string; displayName: string; provisionedBy?: string }[];
	/* `byEmail` only on the single read: who locked them, as a person rather than an account id. */
	lockedLocally?: {
		at: string;
		by: string;
		reason: string;
		byEmail?: string | null;
	};
	/* Known for accounts written since specs/082; absent on older ones, which say nothing either way. */
	passwordSet?: boolean;
};

/* One page of the users list (GET /admin/api/projects/:id/users). */
export interface EndUserPage {
	users: EndUser[];
	totalResults: number;
}

export function usersApi(bucketId: string, userId?: string): string {
	const base = `/admin/api/projects/${encodeURIComponent(bucketId)}/users`;
	return userId ? `${base}/${encodeURIComponent(userId)}` : base;
}

/* The person's name as the directory or the claims give it, when either does. */
export function nameOf(user: EndUser): string | null {
	const display = user.profile?.displayName;
	if (display) return display;
	const claimed = user.claims?.name;
	return typeof claimed === 'string' && claimed ? claimed : null;
}
