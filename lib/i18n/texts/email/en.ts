/*
 * The end-user emails. A text part is one template per email, not a list of sentences, because its line
 * breaks are part of how it reads and a translator may need to move a sentence across them.
 */
export const en = {
	/* Under a button, before the bare URL, for a mail client that does not show buttons. */
	pasteLink: 'Or paste this link into your browser:',
	verification: {
		heading: 'Verify your email',
		intro:
			'Thanks for registering with {app}. Please confirm this email address to activate your account.',
		ignore:
			'If you did not create this account, you can safely ignore this email.',
		link: {
			subject: 'Verify your email for {app}',
			button: 'Verify email',
			text: 'Verify your email for {app}.\n\nOpen this link to confirm your address:\n{url}\n\nIf you did not create this account, you can ignore this email.'
		},
		code: {
			subject: 'Your {app} verification code',
			prompt: 'Enter this verification code to confirm your address:',
			expiry: 'This code expires shortly. Do not share it with anyone.',
			text: 'Verify your email for {app}.\n\nYour verification code is: {code}\n\nThis code expires shortly. If you did not create this account, you can ignore this email.'
		}
	},
	passwordReset: {
		subject: 'Reset your password for {app}',
		heading: 'Reset your password',
		intro:
			'We received a request to set a new password for your {app} account.',
		button: 'Choose a new password',
		expiry: 'This link expires in one hour and can be used once.',
		/* Doing nothing leaves the existing password working: the reader has nothing to do and nothing to fear. */
		ignore:
			'If you did not ask to reset your password, you can safely ignore this email — your current password still works.',
		text: 'Reset your password for {app}.\n\nOpen this link to choose a new password:\n{url}\n\nThis link expires in one hour and can be used once.\n\nIf you did not ask to reset your password, you can ignore this email — your current password still works.'
	},
	invitation: {
		subject: 'Set your password for {bucket}',
		heading: "You're invited to {bucket}",
		intro:
			'An administrator created an account for you at {bucket}. Choose a password to start signing in.',
		button: 'Set your password',
		expiry:
			'The link works for 7 days and can be used once. Setting a password also confirms this email address.',
		ignore:
			'If you were not expecting this, you can ignore this email — nothing happens until a password is chosen.',
		text: "You're invited to {bucket}.\n\nAn administrator created an account for you. Open this link to choose your password:\n{url}\n\nThe link works for 7 days and can be used once. Setting a password also confirms this email address.\n\nIf you were not expecting this, you can ignore this email — nothing happens until a password is chosen."
	},
	/*
	 * About a person's account at a connected service (specs/118 R12). Never a token, an account id or a project id:
	 * forwarded, the message says what happened and links to the page, nothing more.
	 */
	connectedAccount: {
		brokenSubject: 'Reconnect your {service} account at {bucket}',
		brokenHeading: 'Your {service} account needs reconnecting',
		brokenIntro:
			'Your {service} account {label}, connected to {bucket}, no longer works: {service} stopped accepting its access. Applications you allowed to use it cannot, until you connect it again.',
		removedSubject: 'Your {service} account was disconnected from {bucket}',
		removedHeading: 'Your {service} account was disconnected',
		removedIntro:
			'An administrator of {bucket} disconnected your {service} account {label}. Applications you allowed to use it no longer can.',
		serviceRemovedIntro:
			'{bucket} no longer offers {service}, so your {service} account {label} was disconnected. Applications you allowed to use it no longer can.',
		button: 'Open your connected accounts'
	}
} as const;
