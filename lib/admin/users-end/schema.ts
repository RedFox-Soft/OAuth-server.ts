import { t } from 'elysia';

/*
 * The claims an account releases beyond the ones the server derives. Replaced whole by an edit, never
 * merged, so what an operator sends is exactly what the account then holds. Which of them a client
 * actually receives is the `claims` setting's decision, not this record's.
 */
const EndUserClaims = t.Record(t.String(), t.Unknown());

/*
 * Without a password the account holds one nobody knows: the person signs in through an identity provider,
 * or sets one through password reset. Whether its address starts verified is the bucket's policy, not the
 * administrator's say.
 *
 * `invite` mails the person a link to choose their own password (specs/089) instead of an administrator
 * choosing one; it cannot be combined with `password`, which the route refuses with 422.
 */
export const CreateEndUserBody = t.Object({
	email: t.String({ minLength: 3 }),
	password: t.Optional(t.String({ minLength: 8 })),
	claims: t.Optional(EndUserClaims),
	invite: t.Optional(t.Boolean())
});

const ProfileString = t.String({ maxLength: 256 });
const ProfileContact = t.Object(
	{
		value: ProfileString,
		type: t.Optional(t.String({ maxLength: 64 })),
		primary: t.Optional(t.Boolean())
	},
	{ additionalProperties: false }
);

/*
 * A local person's profile as an administrator writes it (specs/089): the stored `EndUserProfile`
 * (lib/adapters/types.ts) restated with Elysia's `t`, because a TypeBox schema from the store module is a
 * different type to Elysia's declarations. The service takes this body as an `EndUserProfile`, so tsc refuses
 * a field here the store does not hold. Closed, as the stored shape is.
 */
export const EndUserProfileBody = t.Object(
	{
		name: t.Optional(
			t.Object(
				{
					formatted: t.Optional(t.String({ maxLength: 2048 })),
					familyName: t.Optional(ProfileString),
					givenName: t.Optional(ProfileString),
					middleName: t.Optional(ProfileString),
					honorificPrefix: t.Optional(ProfileString),
					honorificSuffix: t.Optional(ProfileString)
				},
				{ additionalProperties: false }
			)
		),
		displayName: t.Optional(ProfileString),
		nickName: t.Optional(ProfileString),
		title: t.Optional(ProfileString),
		preferredLanguage: t.Optional(ProfileString),
		locale: t.Optional(ProfileString),
		timezone: t.Optional(ProfileString),
		phoneNumbers: t.Optional(t.Array(ProfileContact, { maxItems: 10 })),
		emails: t.Optional(t.Array(ProfileContact, { maxItems: 10 })),
		enterprise: t.Optional(
			t.Object(
				{
					employeeNumber: t.Optional(ProfileString),
					costCenter: t.Optional(ProfileString),
					organization: t.Optional(ProfileString),
					division: t.Optional(ProfileString),
					department: t.Optional(ProfileString),
					manager: t.Optional(
						t.Object({ value: ProfileString }, { additionalProperties: false })
					)
				},
				{ additionalProperties: false }
			)
		)
	},
	{ additionalProperties: false }
);

/* `profile` replaces the person's whole profile; a field left out is cleared. */
export const UpdateEndUserBody = t.Object({
	active: t.Optional(t.Boolean()),
	claims: t.Optional(EndUserClaims),
	profile: t.Optional(EndUserProfileBody)
});

/*
 * The people one bulk act applies to, by id (specs/089). Ids rather than a filter, so a person who joined the
 * list while the administrator was deciding is never included. A hundred at most, so a request finishes in an
 * ordinary request's time and its answer fits on a screen.
 */
export const BulkUsersBody = t.Object(
	{
		userIds: t.Array(t.String({ minLength: 1, maxLength: 128 }), {
			minItems: 1,
			maxItems: 100
		})
	},
	{ additionalProperties: false }
);

/* `signOut` ends every session and token the account holds in the same request; without it they are kept. */
export const ResetPasswordBody = t.Object({
	password: t.String({ minLength: 8 }),
	signOut: t.Optional(t.Boolean())
});

/*
 * A new login address. Unverified from the moment it is set, whoever typed it; nothing is mailed by the change
 * itself — the verification route sends a message when the administrator asks for one.
 */
export const ChangeEndUserEmailBody = t.Object(
	{ email: t.String({ minLength: 3, maxLength: 254 }) },
	{ additionalProperties: false }
);

/*
 * The users list's query. Strings, as every query value arrives, with the allowed values spelled as literals
 * so an agent reads them from the published schema; the handler turns the numbers into numbers.
 *
 * `q` is the start of an email or a username, in any letter case, or an exact id. `managedBy` is `console`
 * for the people administrators manage here, or a provisioning connection's id for that connection's people.
 */
export const UserListQuery = t.Object(
	{
		q: t.Optional(t.String({ minLength: 1, maxLength: 254 })),
		status: t.Optional(
			t.Union([
				t.Literal('active'),
				t.Literal('deactivated'),
				t.Literal('locked')
			])
		),
		managedBy: t.Optional(t.String({ minLength: 1, maxLength: 128 })),
		verified: t.Optional(t.Union([t.Literal('yes'), t.Literal('no')])),
		authenticator: t.Optional(t.Union([t.Literal('yes'), t.Literal('no')])),
		/* 1-based, as SCIM's is. Default 1. */
		startIndex: t.Optional(t.String({ pattern: '^[1-9][0-9]{0,8}$' })),
		/* 1–200. Default 50. */
		count: t.Optional(
			t.String({ pattern: '^(?:[1-9]|[1-9][0-9]|1[0-9][0-9]|200)$' })
		)
	},
	{ additionalProperties: false }
);

/*
 * Checked against the raw URL by the route, because Elysia only lifts declared keys out of the query string:
 * a mistyped `staus=` would otherwise be dropped and answered with everyone. Derived from the schema so the
 * two cannot disagree.
 */
export const ALLOWED_USER_LIST_PARAMS: ReadonlySet<string> = new Set(
	Object.keys(UserListQuery.properties)
);

/*
 * Why an administrator locked a user. Kept on the record rather than in the audit trail: it may name a person
 * or an incident, and the trail is kept longer than the account.
 */
export const LockEndUserBody = t.Object({
	reason: t.String({ minLength: 1, maxLength: 500 })
});
