import { t } from 'elysia';

/*
 * A new administrator is never a super administrator: the instance privilege is granted by its own
 * operation (`POST /admin/api/admins/:id/super-admin`), so creating an account cannot hand it out.
 */
export const CreateAdminBody = t.Object({
	email: t.String({ format: 'email' }),
	password: t.String({ minLength: 12 })
});

/*
 * `email` corrects an administrator's address. The account is unverified at the new one until its holder
 * proves it, which is why a super administrator may not change their own while administrators must verify
 * theirs: a mistyped address would lock out the person who made the change.
 */
export const UpdateAdminBody = t.Object({
	active: t.Optional(t.Boolean()),
	email: t.Optional(t.String({ format: 'email' }))
});
