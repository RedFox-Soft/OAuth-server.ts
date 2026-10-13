/*
 * Every word the consent page shows, in one place.
 *
 * The page is read by people deciding whether to hand an application access to their account, most of
 * whom have never heard of a scope. So the wording is plain on purpose — one idea per sentence, no
 * protocol terms — and it lives here rather than in the component so that a translation is a change to
 * this file alone, and so a test asserts the sentence the page shows instead of retyping it.
 *
 * Names and hosts are inserted by the component, never by string concatenation of untrusted text into
 * markup: the formatters here return plain strings that React escapes.
 */

export const CONSENT_TEXTS = {
	pageTitle: 'Allow access',

	headline: {
		signIn: (name: string) => `Sign in to ${name}`,
		ownAccess: (name: string, service: string) =>
			`${name} wants access to your ${service} account`,
		// The name sits in the component between the two halves, inside <bdi>, so it cannot reorder them.
		appBefore: 'The app “',
		appAfter: '” wants access to your account',
		device: 'Allow access to a device?'
	},

	host: {
		label: 'App address',
		documentLabel: 'App published at',
		privateUse: (scheme: string, service: string) =>
			`An app on this device (${scheme}) — ${service} can't check which one`,
		notChecked: (service: string) => `${service} hasn't checked this app`
	},

	account: {
		signedInAs: 'Signed in as',
		switch: 'Switch account'
	},

	signIn: {
		shares: (service: string) => `${service} will share with the app:`,
		confirmsIdentity: (service: string) =>
			`${service} will confirm to the app that it is you.`,
		noPassword: 'The app will not get your password.'
	},

	groups: {
		see: 'The app will be able to see:',
		act: 'The app will be able to act for you:',
		other: 'Other permissions — not described:'
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
		codesIn: (codes: string, resource: string) => `${codes} in ${resource}`,
		undescribedOwner: (owner: string) =>
			`The owner of ${owner} hasn't described these:`,
		undescribedAdministrator: (service: string) =>
			`${service}'s administrator hasn't described these:`
	},

	rarFields: {
		actions: 'Actions',
		locations: 'Locations',
		datatypes: 'Data types',
		privileges: 'Privileges',
		identifier: 'Identifier'
	},

	lifetime: (date: string) =>
		`The app keeps this access until ${date}, even when you're not using it.`,

	repeat: {
		alreadyAllowed: 'You already allowed:',
		alsoAsks: 'Now the app also asks:',
		nothingNew:
			'Nothing new is asked. The app gets only what you allowed before:',
		afterApproval: 'After you allow, the app will be able to:'
	},

	nothingRequested: {
		before: '“',
		after: '” isn’t asking for any of your data.'
	},

	warning: {
		hiddenPrefix: 'Warning:',
		adminTitle: 'Administrator rights.',
		admin: (service: string) =>
			`The app will be able to do anything you can do in the ${service} console, such as deleting apps, users and keys.`,
		loopbackBefore: (service: string) =>
			`A program on this computer will receive the answer. ${service} can't tell which one. Continue only if you just started “`,
		loopbackAfter: '” yourself.',
		deviceQuestion: 'Is this code shown on your device?',
		deviceSent: 'If someone sent you this code, choose Don’t allow.',
		deviceRequested: (ago: string) => `Requested ${ago}.`,
		unverifiedBefore: '“',
		unverifiedAfter: (host: string) =>
			`” chose its name itself. Continue only if you started this on ${host} yourself.`,
		unverifiedAfterNoHost:
			'” chose its name itself. Continue only if you started this yourself.',
		hostMismatch: 'The app’s address and where it sends you are different.'
	},

	device: {
		client: 'The app on the device where this code was entered:',
		next: 'Then return to your device.'
	},

	next: {
		loopback: 'Next, a program on this computer receives the answer.'
	},

	buttons: {
		deny: 'Don’t allow',
		allow: 'Allow',
		cancel: 'Cancel',
		continue: 'Continue'
	}
} as const;

/* "a, b and c" — the joining a sentence needs, so a list reads as one. */
export function joinList(items: readonly string[]): string {
	if (items.length <= 1) return items.join('');
	return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
}
