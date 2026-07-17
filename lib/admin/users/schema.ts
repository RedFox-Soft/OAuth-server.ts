import { t } from 'elysia';

export const CreateAdminBody = t.Object({
	email: t.String({ format: 'email' }),
	password: t.String({ minLength: 12 }),
	roles: t.Array(
		t.Union([t.Literal('super_admin'), t.Literal('project_admin')])
	)
});

export const UpdateAdminBody = t.Object({
	roles: t.Optional(
		t.Array(t.Union([t.Literal('super_admin'), t.Literal('project_admin')]))
	),
	active: t.Optional(t.Boolean())
});
