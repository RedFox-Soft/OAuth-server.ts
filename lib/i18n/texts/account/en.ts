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
		'This request did not come from your connected apps page, so nothing was changed.',
	/*
	 * The connected-services page (specs/117): the person's accounts at other services, connected here. A service
	 * name or an account label is always a value, never part of the sentence.
	 */
	servicesTitle: 'Connected services',
	servicesIntro:
		'These are your accounts at other services that you connected here. You can disconnect one at any time.',
	servicesEmpty: 'You have not connected any accounts.',
	servicesAvailable: 'Connect an account',
	servicesLink: 'Connected services',
	appsLink: 'Connected apps',
	connect: 'Connect {service}',
	connectedAt: 'Connected {date}',
	scopesGranted: 'Allowed: {scopes}',
	scopesMissing: 'Not allowed: {scopes}',
	needsReconnection: 'Needs to be connected again',
	disconnect: 'Disconnect',
	connectTitle: 'Connect your {service} account?',
	connectEffect:
		'You will go to {service} to sign in and allow access. You can disconnect the account here at any time.',
	continue: 'Continue',
	disconnectTitle: 'Disconnect {account}?',
	disconnectEffect:
		'This account at {service} will be forgotten here, and {service} will be asked to cancel the access it gave.',
	connectedDone: 'Your {service} account is connected.',
	updatedDone: 'Your {service} account is connected again.',
	disconnectedDone: 'The account was disconnected.',
	revocationRevoked: '{service} was asked to cancel the access and agreed.',
	revocationFailed:
		'{service} could not be reached to cancel the access. Remove it there yourself.',
	revocationNotSupported:
		'{service} does not let this server cancel the access. Remove it there yourself.',
	revocationUnreadable:
		'The account could no longer be read here, so {service} was not asked to cancel the access. Remove it there yourself.',
	manageAccess: 'Open the access settings at {service}',
	noticeDeclined: 'The account was not connected: access was not allowed.',
	noticeFailed: 'The account could not be connected. Try again.',
	noticeLimit:
		'You have connected as many accounts at this service as you can. Disconnect one first.',
	noticeUnavailable: 'This service cannot be connected right now.',
	noticeExpired: 'Connecting took too long. Try again.',
	noticeRefused:
		'The account was not connected: the answer did not belong to the connection started here.'
} as const;
