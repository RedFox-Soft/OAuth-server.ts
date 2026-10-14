/*
 * Every word the connected-applications page shows (specs/095).
 */

export const en = {
	/*
	 * The name of the page's own client, which this server synthesizes and never stores (lib/account_page/client.ts).
	 * A client has one name, so it stays in English wherever the page itself is shown.
	 */
	clientName: 'Your account page',
	title: 'Connected apps',
	signedInAs: 'Signed in as {email}',
	signOut: 'Sign out',
	intro:
		'These apps can get at your account. Removing one signs you out of it, and it will have to ask you again before it gets back in.',
	empty: 'No apps have access to your account.',
	deletedApp: 'An application that no longer exists',
	signsInAt: 'Signs you in at {hosts}',
	signsInAtMore: {
		one: 'Signs you in at {hosts} and {count} more',
		other: 'Signs you in at {hosts} and {count} more'
	},
	onThisDevice: 'An app on this device',
	trusted:
		'Part of {service}. It gets the access it asks for without asking you.',
	canSee: 'Can see',
	canDo: 'Can do for you',
	otherAccess: 'Other access',
	confirmIdentity: 'Can confirm who you are',
	technicalNames: 'Technical names',
	given: 'Access given {date}',
	lastToken: 'Last given a token {date}',
	// The page's times are written in UTC whatever the reader's zone, and say so.
	dateTime: '{dateTime} UTC',
	keepsAccess: 'Keeps access after you sign out',
	remove: 'Remove access',
	cancel: 'Cancel',
	confirmTitle: 'Remove access for {app}?',
	confirmEffect: '{app} will be signed out and lose access to your account.',
	confirmAsksAgain: 'It will have to ask you again next time.',
	confirmReturnsSilently:
		'It will sign you in again without asking next time you use it.',
	done: 'Access removed from {app}.',
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
