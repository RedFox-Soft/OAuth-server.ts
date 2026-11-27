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
	/* How it was set up (specs/126): by the person on their own page, or at a sign-in that required one. */
	totpEnrolledVia?: 'self' | 'sign-in' | null;
	/* An administrator removed it: the next one is proved by a mailed link first. */
	totpProofRequired?: true;
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
	/* The person's activity in brief (specs/133), on the single read only. No address, country or device. */
	activity?: ActivitySummaryView;
	/* On the list only (specs/134): the latest day, or month, the person was marked active. */
	lastActive?: ActivitySummaryView['lastActive'];
};

export interface ActivitySummaryView {
	recordingBegan: string | null;
	keptDays: number;
	lastSignIn: {
		at: string;
		clientId: string | null;
		name: string | null;
		method: string | null;
	} | null;
	notLetInSince: {
		at: string;
		count: number;
		reason: string;
		kind: 'signIn' | 'app' | 'api';
	} | null;
	lastActive: { day: string } | { month: string } | null;
	/* Apps behind the proxy and APIs the person was let through in the last 90 days, newest first (specs/134). */
	appsUsed?: {
		kind: 'app' | 'api';
		id: string;
		name: string | null;
		lastDay: string;
	}[];
}

/*
 * A person's passkeys as GET …/users/:uid/passkeys answers (specs/140, lib/passkeys/ways_in.ts): each with why it does
 * or does not sign in, the person's other ways in, and how someone left with none gets back.
 */
export interface PasskeyView {
	id: string;
	name?: string;
	createdOn: { browser: string; system: string };
	synced: boolean;
	createdAt: string;
	createdVia:
		| 'passkey'
		| 'password_code'
		| 'password_mail'
		| 'password'
		| 'registration'
		| 'recovery'
		| 'admin_link'
		| 'federated_mail';
	lastUsedAt?: string;
	state: 'works' | 'off' | 'old_address' | 'copied';
	/* False while a passkey made after a password alone is unconfirmed (specs/141). */
	confirmed: boolean;
	/* Present while a recovered passkey is capped at multi_factor (specs/145 Q1=A). */
	recoveredUntil?: string;
}

export interface PasskeysOfPerson {
	passkeys: PasskeyView[];
	ways: { password: boolean; providers: string[] };
	restore: 'self' | 'admin' | 'none';
	mailable: boolean;
}

/* One page of the users list (GET /admin/api/projects/:id/users). */
export interface EndUserPage {
	users: EndUser[];
	totalResults: number;
	/* When counting activity began (specs/134): an empty "Last active" means nothing since then. */
	activeSince?: string | null;
}

/* "Today", a date, or a month when only the month is still known (specs/133 R17, specs/134); "—" for nothing. */
export function lastActiveWords(
	active: ActivitySummaryView['lastActive']
): string {
	if (!active) return '—';
	if ('day' in active) {
		const today = new Date().toISOString().slice(0, 10);
		if (active.day === today) return 'Today';
		return new Date(`${active.day}T12:00:00Z`).toLocaleDateString(undefined, {
			dateStyle: 'medium'
		});
	}
	return new Date(`${active.month}-15T12:00:00Z`).toLocaleDateString(
		undefined,
		{
			month: 'long',
			year: 'numeric'
		}
	);
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
