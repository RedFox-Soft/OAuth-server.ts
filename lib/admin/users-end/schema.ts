import { t } from 'elysia';

export const CreateEndUserBody = t.Object({
	email: t.String({ minLength: 3 }),
	password: t.String({ minLength: 8 }),
	roles: t.Optional(t.Array(t.String()))
});

export const UpdateEndUserBody = t.Object({
	roles: t.Optional(t.Array(t.String())),
	active: t.Optional(t.Boolean())
});

export const ResetPasswordBody = t.Object({
	password: t.String({ minLength: 8 })
});
