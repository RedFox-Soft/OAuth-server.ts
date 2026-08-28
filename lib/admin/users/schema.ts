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

/*
 * The reserved admin bucket's own policy, and deliberately one field of it.
 *
 * The bucket carries nine settings; this exposes the only one that is both meaningful here and safe
 * to hand an operator. The rest are excluded on their own merits, and the exclusions are the point of
 * this schema rather than an accident of scope:
 *
 * - `emailVerificationRequired` would brick the console. Both paths that create an administrator write
 *   `verified: false` — this module's POST and the first-run bootstrap — and no verification mail is
 *   ever sent for this bucket, because `issueAndSend` is only reached from the self-service
 *   registration route, which this bucket refuses. One PATCH would lock every administrator out.
 * - `passwordLogin: false` is a permanent lockout: this bucket accepts no providers, and
 *   `assertSomeWayToSignIn` looks for an enabled provider, so it would not even catch it.
 * - `registrationOpen: true` would let anyone who can reach /admin/login create a row in the reserved
 *   bucket through the ordinary registration page.
 * - `roles` is inert — nothing constrains an administrator's roles against it.
 * - `managedBy` is meaningless where access is by role, `federation` is refused by its own routes and
 *   is a separate decision, and `name` is cosmetic.
 *
 * Any of them arriving here is refused with a 422 rather than dropped, which matters: a field accepted
 * by the route and then discarded by the handler reads to an operator — or an agent — as "the setting
 * was applied". That is the defect lib/admin/clients/service.ts records against its own allow-list
 * builder, and the one the projects route had with `clientIds`.
 *
 * The refusal comes from the app's `normalize: false` (lib/index.ts), not from the line below —
 * measured, not assumed: with normalization on, an undeclared field is stripped before validation and
 * a closed schema behaves exactly like an open one. `additionalProperties: false` is kept anyway so
 * the schema states its own intent instead of depending on how the app was constructed, and
 * test/admin/admin_settings.spec.ts builds its instance the way lib/index.ts does so the assertion
 * describes production rather than the default.
 */
export const AdminSettingsBody = t.Object(
	{
		totpRequired: t.Boolean()
	},
	{ additionalProperties: false }
);
