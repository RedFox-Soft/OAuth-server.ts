/*
 * Every action the console can take, and how much it asks before taking it (specs/079 data-model §3).
 *
 * One table, so the same kind of act asks the same way on every screen:
 *
 * - C0 — nothing. Creating, editing, enabling: undone by the opposite act.
 * - C1 — a plain question. Small, reversible, but easy to hit by mistake.
 * - C2 — a danger question, Cancel focused, consequences stated. Ends access, revokes, replaces or
 *   withdraws something people rely on, or cannot be undone for one object.
 * - C3 — a typed word (ConfirmDestruction). Destroys an unbounded number of things, or a key.
 * - C4 — the server's preview first (PreviewConfirm). Only the server knows the full list of what moves.
 *
 * The classification is the product decision; the dialogs are mechanics. A completeness case in
 * test/admin/console_frame.spec.ts keeps this table and the console's calls in step.
 */

export type ActionClass = 'C0' | 'C1' | 'C2' | 'C3' | 'C4';

export interface ActionSpec {
	readonly class: ActionClass;
	/* The question, given what is acted on. C1 and C2 only. */
	readonly title?: (target: string) => string;
	/* The verb on the confirming button. Defaults to the question's own verb being obvious: "Confirm". */
	readonly okText?: string;
	/* C3: the word typed to confirm. */
	readonly word?: string;
	/* Asked inside the act's own form rather than by useConfirm, because the question needs the form's answer. */
	readonly inline?: boolean;
	/* The word on Cancel, when "Cancel" would not say what declining keeps. */
	readonly cancelText?: string;
}

export const ACTIONS = {
	'project.create': { class: 'C0' },
	'project.origins.save': { class: 'C0' },
	'project.bucket.change': {
		class: 'C2',
		title: (t) => `Change the user bucket of ${t}?`,
		okText: 'Change bucket'
	},
	'project.move': { class: 'C4' },
	'project.delete': { class: 'C3', word: 'delete' },

	'client.create': { class: 'C0' },
	'client.edit': { class: 'C0' },
	'client.secret.rotate': {
		class: 'C2',
		title: (t) => `Rotate the secret of ${t}?`,
		okText: 'Rotate secret'
	},
	'client.delete': {
		class: 'C2',
		title: (t) => `Delete client ${t}?`,
		okText: 'Delete client'
	},

	'resource.declare': { class: 'C0' },
	'resource.edit': { class: 'C0' },
	'resource.remove': {
		class: 'C1',
		title: (t) => `Remove ${t} from this project?`,
		okText: 'Remove'
	},

	'bucket.create': { class: 'C0' },
	'bucket.edit': { class: 'C0' },
	'bucket.move': { class: 'C4' },
	'bucket.rename': { class: 'C0' },
	// The server's preview names every application, connection, provider and resource the change affects.
	'bucket.address.change': { class: 'C4' },
	/*
	 * A sign-in change that can shut people out (specs/083): the server states what it would do, with counts,
	 * and the question lists its lines. Declining keeps the draft, so Cancel says so.
	 */
	'bucket.signIn.confirm': {
		class: 'C2',
		title: (t) => `Save sign-in changes for ${t}?`,
		okText: 'Save changes',
		cancelText: 'Keep editing'
	},
	'bucket.delete': { class: 'C3', word: 'delete' },

	'user.create': { class: 'C0' },
	'user.edit': { class: 'C0' },
	'user.claims.edit': { class: 'C0' },
	'user.activate': { class: 'C0' },
	'user.deactivate': {
		class: 'C2',
		title: (t) => `Deactivate ${t}?`,
		okText: 'Deactivate'
	},
	// The old address stops signing them in, and a message sent to it no longer proves the new one.
	'user.email.change': {
		class: 'C2',
		title: (t) => `Change the email of ${t}?`,
		okText: 'Change email'
	},
	'user.verification.resend': { class: 'C0' },
	'user.password.set': {
		class: 'C2',
		title: (t) => `Set a new password for ${t}?`,
		okText: 'Set password'
	},
	'user.identity.remove': {
		class: 'C1',
		title: (t) => `Remove the linked identity ${t}?`,
		okText: 'Remove'
	},
	// The same act when the link is the only way they can sign in: afterwards nobody can, until someone helps.
	'user.identity.removeOnly': {
		class: 'C2',
		title: (t) => `Remove the linked identity ${t}?`,
		okText: 'Remove'
	},
	'user.connection.assign': {
		class: 'C2',
		title: (t) => `Hand ${t} over to the provisioning connection?`,
		okText: 'Hand over'
	},
	// The lock dialog asks for the reason, which is kept on the record; typing it is the confirmation.
	'user.lock': { class: 'C1', okText: 'Lock', inline: true },
	// Re-admits an account someone judged compromised; the question states when and why it was locked.
	'user.unlock': {
		class: 'C2',
		title: (t) => `Unlock ${t}?`,
		okText: 'Unlock'
	},
	'user.signOut': {
		class: 'C1',
		title: (t) => `Sign ${t} out everywhere?`,
		okText: 'Sign out'
	},
	'user.totp.reset': {
		class: 'C2',
		title: (t) => `Reset the authenticator of ${t}?`,
		okText: 'Reset authenticator'
	},
	'user.delete': {
		class: 'C2',
		title: (t) => `Delete user ${t}?`,
		okText: 'Delete user'
	},

	'userGroup.create': { class: 'C0' },
	'userGroup.rename': { class: 'C0' },
	// The server's preview names the members the directory does not manage (specs/084).
	'userGroup.connection.assign': { class: 'C4' },
	'userGroup.delete': {
		class: 'C2',
		title: (t) => `Delete user group ${t}?`,
		okText: 'Delete user group'
	},
	'userGroup.member.add': { class: 'C0' },
	'userGroup.member.remove': {
		class: 'C1',
		title: (t) => `Remove ${t} from this user group?`,
		okText: 'Remove'
	},

	'provider.connect': { class: 'C0' },
	'provider.create': { class: 'C0' },
	'provider.edit': { class: 'C0' },
	'provider.enable': { class: 'C0' },
	'provider.disable': {
		class: 'C2',
		title: (t) => `Disable sign-in with ${t}?`,
		okText: 'Disable'
	},
	/*
	 * A provider change that lets more people in (specs/084): creating accounts, dropping a domain limit,
	 * linking by email, accepting a logout signal. Declining keeps the draft.
	 */
	'provider.trust.widen': {
		class: 'C2',
		title: (t) => `Save changes to ${t}?`,
		okText: 'Save changes',
		cancelText: 'Keep editing'
	},
	'provider.delete': {
		class: 'C2',
		title: (t) => `Delete identity provider ${t}?`,
		okText: 'Delete provider'
	},

	'connection.create': { class: 'C0' },
	'connection.enable': { class: 'C0' },
	'connection.disable': {
		class: 'C2',
		title: (t) => `Disable provisioning connection ${t}?`,
		okText: 'Disable'
	},
	'connection.delete': {
		class: 'C2',
		title: (t) => `Delete provisioning connection ${t}?`,
		okText: 'Delete connection'
	},
	'connection.credential.issue': {
		class: 'C2',
		title: (t) => `Issue a new credential for ${t}?`,
		okText: 'Issue credential'
	},
	// One slot per kind: the old credential stops working the moment the new one exists.
	'connection.credential.replace': {
		class: 'C2',
		title: (t) => `Replace the credential of ${t}?`,
		okText: 'Replace credential'
	},
	'connection.credential.revoke': {
		class: 'C1',
		title: (t) => `Revoke the credential of ${t}?`,
		okText: 'Revoke'
	},
	'connection.guard.save': { class: 'C0' },
	'connection.guard.off': {
		class: 'C2',
		title: (t) => `Turn off the deprovisioning guard of ${t}?`,
		okText: 'Turn off'
	},
	'connection.hold.release': { class: 'C3', word: 'release' },

	'key.generate': { class: 'C0' },
	'key.promote': {
		class: 'C1',
		title: (t) => `Make ${t} the signing key?`,
		okText: 'Make signing key'
	},
	'key.retire': { class: 'C3', word: 'retire' },

	'group.create': { class: 'C0' },
	'group.delete': {
		class: 'C2',
		title: (t) => `Delete group ${t}?`,
		okText: 'Delete group'
	},
	'group.member.add': { class: 'C0' },
	'group.member.promote': { class: 'C0' },
	'group.member.demote': {
		class: 'C2',
		title: (t) => `Make ${t} a member instead of an owner?`,
		okText: 'Make member'
	},
	'group.member.remove': {
		class: 'C2',
		title: (t) => `Remove ${t} from this group?`,
		okText: 'Remove'
	},

	'admin.create': { class: 'C0' },
	'admin.superAdmin.grant': {
		class: 'C2',
		title: (t) => `Make ${t} a super administrator?`,
		okText: 'Make super administrator'
	},
	'admin.superAdmin.withdraw': {
		class: 'C2',
		title: (t) => `Withdraw super administration from ${t}?`,
		okText: 'Withdraw'
	},
	// Ends their access to the console at once; their account, groups and history are kept.
	'admin.deactivate': {
		class: 'C2',
		title: (t) => `Deactivate ${t}?`,
		okText: 'Deactivate'
	},
	// Gives back everything their groups grant, so it is asked like the act it undoes.
	'admin.activate': {
		class: 'C2',
		title: (t) => `Activate ${t}?`,
		okText: 'Activate'
	},
	'admin.signOut': {
		class: 'C1',
		title: (t) => `Sign ${t} out everywhere?`,
		okText: 'Sign out'
	},
	'admin.totp.reset': {
		class: 'C2',
		title: (t) => `Reset the authenticator of ${t}?`,
		okText: 'Reset authenticator'
	},
	'admin.email.change': {
		class: 'C2',
		title: (t) => `Change the sign-in email of ${t}?`,
		okText: 'Change email'
	},

	// The route states what the permit would grant; the form shows it and its danger OK is the consent.
	'agentAccess.permit': { class: 'C2', okText: 'Permit', inline: true },
	'agentAccess.keyProof': {
		class: 'C2',
		title: (t) => `Change the key-proof requirement for ${t}?`,
		okText: 'Change'
	},
	'agentAccess.withdraw': {
		class: 'C2',
		title: (t) => `Withdraw ${t}?`,
		okText: 'Withdraw'
	},

	// The save bar asks its own question when a change is risky (settings/SaveBar.tsx).
	'settings.save': { class: 'C0' },
	'settings.discard': {
		class: 'C1',
		title: (t) => `Discard ${t}?`,
		okText: 'Discard'
	},
	'smtp.save': { class: 'C0' },
	'sentry.save': { class: 'C0' },
	'sentry.disable': {
		class: 'C2',
		title: () => 'Stop reporting faults to Sentry?',
		okText: 'Disable'
	},
	'faults.purge': { class: 'C4' },
	'scope.switch': { class: 'C0' },
	'self.verification.send': { class: 'C0' }
} as const satisfies Record<string, ActionSpec>;

export type ActionId = keyof typeof ACTIONS;
