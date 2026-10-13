/*
 * Every word the connected-applications page shows (specs/095), in one place so that a later translation
 * replaces a catalog rather than hunting through markup. English only for now.
 */

export const ACCOUNT_PAGE_TEXTS = {
	clientName: 'Your account page',
	title: 'Connected apps',
	signedInAs: 'Signed in as',
	signOut: 'Sign out',
	intro:
		'These apps can get at your account. Removing one signs you out of it, and it will have to ask you again before it gets back in.',
	empty: 'No apps have access to your account.',
	deletedApp: 'An application that no longer exists',
	hosts: (hosts: readonly string[], more: number): string =>
		`Signs you in at ${hosts.join(', ')}${more > 0 ? ` and ${more} more` : ''}`,
	onThisDevice: 'An app on this device',
	trusted: (service: string): string =>
		`Part of ${service}. It gets the access it asks for without asking you.`,
	canSee: 'Can see',
	canDo: 'Can do for you',
	other: 'Other access',
	confirmIdentity: 'Can confirm who you are',
	technicalNames: 'Technical names',
	given: 'Access given',
	lastToken: 'Last given a token',
	keepsAccess: 'Keeps access after you sign out',
	remove: 'Remove access',
	cancel: 'Cancel',
	confirmTitle: (name: string): string => `Remove access for ${name}?`,
	confirmEffect: (name: string): string =>
		`${name} will be signed out and lose access to your account.`,
	confirmAsksAgain: 'It will have to ask you again next time.',
	confirmReturnsSilently:
		'It will sign you in again without asking next time you use it.',
	done: (name: string): string => `Access removed from ${name}.`,
	gone: 'That app no longer has access to your account.',
	expiredTitle: 'This sign-in has expired',
	expired:
		'The sign-in for your connected apps page took too long or was started somewhere else.',
	notSignedInTitle: "You didn't sign in",
	notSignedIn: 'Your connected apps page needs you to sign in.',
	failedTitle: 'Something went wrong',
	failed: 'We could not sign you in to your connected apps page.',
	tryAgain: 'Go to your connected apps page',
	refusedTitle: 'Request refused',
	refused:
		'This request did not come from your connected apps page, so nothing was changed.'
} as const;
