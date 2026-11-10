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
		'The account was not connected: the answer did not belong to the connection started here.',
	/* Which applications may use an account (specs/118): given and withdrawn here. */
	agentsHeading: 'Applications that may use it',
	agentsNone: 'No application may use it.',
	agentUsed: 'last used {date}',
	agentNotUsed: 'not used yet',
	withdraw: 'Withdraw',
	allowHeading: 'Let an application use it',
	allow: 'Allow',
	allowedDone: '{app} may now use your {service} account.',
	withdrawnDone:
		'{app} can no longer get access to your {service} account. Access it already got stays valid at {service} until it expires, usually within an hour.',
	/* An agent's connect link (specs/119): the sentence in the refusal, and the link's pages. */
	linkMessageConnect:
		'Open this link to connect your {service} account and let {app} use it.',
	linkMessageConsent: 'Open this link to let {app} use your {service} account.',
	linkMessageReconnect: 'Open this link to reconnect your {service} account.',
	linkConnectTitle: '{app} asks to use your {service} account',
	linkConnectEffect:
		'You will go to {service} to sign in and allow access. {app} will then be able to use the account. You can withdraw this on your account page at any time.',
	linkConnectButton: 'Connect {service} and allow {app}',
	linkConnectAnother: 'Connect another {service} account',
	connectedAtSignIn: 'Connected when you signed in with {provider}.',
	linkLimit:
		'You have connected as many {service} accounts as you can. You can let {app} use one of them instead.',
	linkConsentOne: 'Let {app} use your {service} account {account}?',
	linkConsentSeveral: 'Which of your {service} accounts may {app} use?',
	linkConsentNote: 'You can withdraw this on your account page at any time.',
	linkReconnectTitle: 'Reconnect your {service} account {account}',
	linkReconnectEffect:
		'{service} no longer accepts your account {account}. Reconnect it so {app} can use it again.',
	linkReconnectButton: 'Reconnect {service}',
	linkDecline: 'Decline',
	linkTryAgain: 'You can try again from this link while it is valid.',
	linkDoneTitle: 'Done',
	linkDoneConnected:
		'Your {service} account is connected and {app} can use it.',
	linkDoneConnectedOnly:
		'Your {service} account is connected, but {app} may no longer use {service}.',
	linkDoneAllowed: '{app} can now use your {service} account.',
	linkDoneReconnected: 'Your {service} account {account} works again.',
	linkDoneOther:
		'Another {service} account was connected. {account} still needs to be connected again.',
	linkAlreadyDone: 'This was already done.',
	linkReturn: 'You can return to {app}.',
	linkDeclinedTitle: 'Nothing was changed',
	linkDeclined:
		'{app} cannot use your {service} account. You can return to {app}.',
	linkInvalidTitle: 'This link is no longer valid',
	linkInvalid: 'Ask the application for a new one.',
	linkOtherTitle: 'This link is for another account',
	linkOther:
		'It was made for someone else, so nothing was changed. Sign out first if you meant to use another account.',
	linkChangedTitle: 'This can no longer be done',
	linkChangedService: 'This service is no longer offered here.',
	linkChangedApp: '{app} may no longer use {service}.',
	linkChangedAccess:
		'{app} no longer has access to your account here. Sign in to it again to give it access.',
	linkChangedAccount: 'That {service} account is no longer connected.',
	/*
	 * The person's own two-step verification (specs/126). People read "a code from an authenticator app"; "TOTP" never
	 * appears here. A value — an address, a date, a provider's name — is always a value, never part of a sentence.
	 */
	securityLink: 'Two-step verification',
	securityTitle: 'Two-step verification',
	securityOff:
		'Off. Signing in to {service} with your password needs only the password.',
	securityExplain:
		'Turn it on, and after your password you also type a 6-digit code from an authenticator app on your phone. Someone who learns your password still cannot sign in.',
	securityNeeds:
		'You will need an authenticator app on your phone, for example Google Authenticator, Microsoft Authenticator or 1Password, and your email, {email}.',
	securityLostPhone:
		'If you lose your phone, you cannot sign in until the people who run {service} remove it from your account.',
	securityStart: 'Turn on two-step verification',
	securitySentTitle: 'Check your email',
	securitySent:
		'We sent a link to {email}. Open it in this browser within 10 minutes to continue.',
	securityResend: 'Send a new link',
	securityAddTitle: 'Add {service} to your authenticator app',
	securityScan: 'Scan this code with your authenticator app.',
	securityQrLabel: 'QR code for your authenticator app',
	securityKey: 'Cannot scan it? Type this key in the app:',
	securityOpenApp: 'On this phone? Open it in your authenticator app',
	securitySpare: 'Tip: scan it with a second device too, to keep a spare.',
	securityCodeLabel: 'Code from the authenticator app',
	securityTurnOn: 'Turn on',
	securityWrongCode: 'That code did not work. Type the code the app shows now.',
	securityOnTitle: 'Two-step verification is on',
	securityOnSince: 'On since {date}.',
	securityOnEvery:
		'Every time you sign in to {service} with your password, you also type a code from your authenticator app. That is in every app where you sign in with your {service} account.',
	securityProvider:
		'Signing in with {provider} does not ask for this code; {provider} protects that sign-in itself.',
	securityReplace: 'Use a different phone',
	securityTurnOff: 'Turn off',
	securityRequired:
		'{service} asks everyone for a code, so it cannot be turned off.',
	securityOffConfirmTitle: 'Turn off two-step verification?',
	securityOffConfirm: 'Signing in to {service} will need only your password.',
	securityNoPassword:
		'You sign in through a provider, so two-step verification here isn’t used for your account. Apps of {service} that require a code from an authenticator app can’t be opened through a provider sign-in.',
	securityUnavailable:
		'The people who run {service} have not made two-step verification available here.',
	securitySignInWithPassword:
		'To set this up, sign in with your password, not through a provider.',
	securityDoneOn:
		'Two-step verification is on. We sent a confirmation to {email}.',
	securityDoneChanged:
		'Your new authenticator app is set up. Codes from the old one no longer work.',
	securityDoneOff: 'Two-step verification is off.',
	securityThrottled: 'You have asked for several emails. Try again later.',
	securityMailFailed: 'We could not send the email. Try again later.',
	securityLinkInvalid:
		'This link does not work here. Open the newest link in the browser where you started, within 10 minutes.',
	securityChanged: 'Something changed while you were doing this. Start again.',
	disownTitle: 'Remove two-step verification from {email}?',
	disownEffect:
		'This removes the authenticator app that was just set up and signs your account out everywhere. Then change your password.',
	disownButton: 'Remove it',
	disownDoneTitle: 'Two-step verification was removed',
	disownDone:
		'Your account is signed out everywhere. Change your password now: on the {service} sign-in page, choose "{forgot}".',
	disownNothingTitle: 'Nothing was changed',
	disownNothing:
		'This link no longer works. If someone else set up two-step verification on your account, ask the people who run {service}.'
} as const;
