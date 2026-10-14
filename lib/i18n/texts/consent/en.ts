/*
 * Every word the consent page shows.
 *
 * The page is read by people deciding whether to hand an application access to their account, most of whom have
 * never heard of a scope. So the wording is plain on purpose — one idea per sentence, no protocol terms. Each
 * entry is a whole sentence: the application's name, the service's name, a date or a list goes into a `{slot}`,
 * never between two halves, so a translation can put it where its language wants it.
 */

export const en = {
	pageTitle: 'Allow access',

	headline: {
		signIn: 'Sign in to {app}',
		ownAccess: '{app} wants access to your {service} account',
		app: 'The app “{app}” wants access to your account',
		device: 'Allow access to a device?'
	},

	host: {
		label: 'App address',
		documentLabel: 'App published at',
		privateUse:
			"An app on this device ({scheme}) — {service} can't check which one",
		notChecked: "{service} hasn't checked this app"
	},

	account: {
		signedInAs: 'Signed in as {account}',
		switch: 'Switch account'
	},

	signIn: {
		shares: '{service} will share with the app:',
		confirmsIdentity: '{service} will confirm to the app that it is you.',
		noPassword: 'The app will not get your password.'
	},

	groups: {
		see: 'The app will be able to see:',
		act: 'The app will be able to act for you:',
		undescribed: 'Other permissions — not described:'
	},

	categories: {
		profile: 'your name and profile photo',
		profileName: 'your name',
		profilePhoto: 'your profile photo',
		profileDetails: 'other details on your profile',
		email: 'your email address',
		address: 'your postal address',
		phone: 'your phone number',
		groups: 'the groups you belong to'
	},

	resource: {
		heading: 'In',
		technicalNames: 'Technical names',
		codesIn: '{codes} in {resource}',
		undescribedOwner: "The owner of {owner} hasn't described these:",
		undescribedAdministrator:
			"{service}'s administrator hasn't described these:"
	},

	rarFields: {
		actions: 'Actions',
		locations: 'Locations',
		datatypes: 'Data types',
		privileges: 'Privileges',
		identifier: 'Identifier'
	},

	lifetime:
		"The app keeps this access until {date}, even when you're not using it.",

	repeat: {
		alreadyAllowed: 'You already allowed: {items}.',
		alsoAsks: 'Now the app also asks:',
		nothingNew:
			'Nothing new is asked. The app gets only what you allowed before: {items}.',
		afterApproval: 'After you allow, the app will be able to:',
		afterApprovalItems: '{items}.',
		afterApprovalItemsAndChoice: '{items}, and anything you select above.'
	},

	choices: {
		fixedHeading: 'Needed to sign you in:',
		refusedBefore: 'You didn’t allow this last time',
		offline: 'Keep access when you’re not using it',
		offlineUntil: 'Until {date}',
		rarTogether: 'These are allowed together with the rest, or not at all.'
	},

	nothingRequested: '“{app}” isn’t asking for any of your data.',

	warning: {
		hiddenPrefix: 'Warning:',
		adminTitle: 'Administrator rights.',
		admin:
			'The app will be able to do anything you can do in the {service} console, such as deleting apps, users and keys.',
		loopback:
			"A program on this computer will receive the answer. {service} can't tell which one. Continue only if you just started “{app}” yourself.",
		deviceQuestion: 'Is this code shown on your device?',
		deviceSent: 'If someone sent you this code, choose Don’t allow.',
		deviceRequested: 'Requested {ago}.',
		justNow: 'just now',
		unverified:
			'“{app}” chose its name itself. Continue only if you started this on {host} yourself.',
		unverifiedNoHost:
			'“{app}” chose its name itself. Continue only if you started this yourself.',
		hostMismatch: 'The app’s address and where it sends you are different.'
	},

	device: {
		client: 'The app on the device where this code was entered:',
		next: 'Then return to your device.'
	},

	next: {
		loopback: 'Next, a program on this computer receives the answer.'
	},

	/* The application's own pages, linked below the buttons for an app of this organization (specs/094). */
	links: {
		label: 'About {app}',
		policy: '{app}’s privacy policy',
		terms: '{app}’s terms of service',
		external: ' (opens an external site in a new tab)'
	},

	/* Where the access can be taken back (specs/095). */
	revokeHint: {
		sentence: 'You can remove this access at any time on your {link}.',
		link: 'connected apps page'
	},

	buttons: {
		deny: 'Don’t allow',
		allow: 'Allow',
		cancel: 'Cancel',
		continue: 'Continue'
	}
} as const;
