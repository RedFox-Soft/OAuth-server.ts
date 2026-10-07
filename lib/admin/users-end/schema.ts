import { t } from 'elysia';

/*
 * The claims an account releases beyond the ones the server derives. Replaced whole by an edit, never
 * merged, so what an operator sends is exactly what the account then holds. Which of them a client
 * actually receives is the `claims` setting's decision, not this record's.
 */
const EndUserClaims = t.Record(t.String(), t.Unknown());

export const CreateEndUserBody = t.Object({
	email: t.String({ minLength: 3 }),
	password: t.String({ minLength: 8 }),
	claims: t.Optional(EndUserClaims)
});

export const UpdateEndUserBody = t.Object({
	active: t.Optional(t.Boolean()),
	claims: t.Optional(EndUserClaims)
});

export const ResetPasswordBody = t.Object({
	password: t.String({ minLength: 8 })
});

/*
 * Why an administrator locked a user. Kept on the record rather than in the audit trail: it may name a person
 * or an incident, and the trail is kept longer than the account.
 */
export const LockEndUserBody = t.Object({
	reason: t.String({ minLength: 1, maxLength: 500 })
});
