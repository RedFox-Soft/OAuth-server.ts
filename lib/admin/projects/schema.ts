import { t } from 'elysia';

/*
 * `corsOrigins` is typed only as an array of strings here. The origin rule itself lives in
 * lib/helpers/cors_origin.ts and runs in the handler, so a rejection returns the admin_error shape and
 * can name the offending value — a TypeBox pattern would produce a generic validation error that tells
 * an operator nothing about which entry was wrong or what it should have been.
 */
export const CreateProjectBody = t.Object({
	name: t.String({ minLength: 1 }),
	slug: t.String({ pattern: '^[a-z0-9-]+$' }),
	corsOrigins: t.Optional(t.Array(t.String()))
});

export const UpdateProjectBody = t.Object({
	name: t.Optional(t.String({ minLength: 1 })),
	corsOrigins: t.Optional(t.Array(t.String()))
});

/*
 * Moving a project with no bucket to another administrator group (specs/075). A project that uses a
 * bucket moves with it, through the bucket's own route. `confirm` is the second call, after the preview.
 */
export const MoveProjectOwnerBody = t.Object({
	groupId: t.String({ minLength: 1 }),
	confirm: t.Optional(t.Boolean())
});

/*
 * Changing a project's bucket changes the issuer of every application in it, so it is two calls (specs/085):
 * without `confirm` the route answers with a preview and changes nothing; `confirm` with the preview's
 * `expect` applies it. The counts are what the consent was given to — an application or a declaration that
 * arrived since was not on the screen, so a mismatch answers with the fresh preview instead.
 *
 * Whole numbers by `multipleOf`, as the bucket address change spells them: `t.Integer` coerces through a
 * string branch.
 */
const BucketChangeExpect = t.Object({
	applications: t.Number({ minimum: 0, multipleOf: 1 }),
	resources: t.Number({ minimum: 0, multipleOf: 1 })
});

export const SetBucketBody = t.Object({
	bucketId: t.String(),
	confirm: t.Optional(t.Literal(true)),
	expect: t.Optional(BucketChangeExpect)
});

/* Clearing is the same change towards the default bucket. The body is optional; without one it previews. */
export const ClearBucketBody = t.Object({
	confirm: t.Optional(t.Literal(true)),
	expect: t.Optional(BucketChangeExpect)
});

/*
 * What a project deletion may take with it, and what the caller reviewed before deciding.
 *
 * `cascade` is a literal rather than a boolean so the parameter says what it destroys. A future
 * second kind would be a second literal, where `cascade=true` would have had to mean "everything",
 * which is the one thing a destructive election must never be able to mean by default.
 *
 * `client` is the set the console displayed. It is here rather than inferred from the project
 * because consent is given for what was on the screen: a client that arrived while the administrator
 * was reading the list is one nobody reviewed, and destroying it on the strength of their "yes" is
 * the failure this parameter exists to make impossible. Typed as a union because a repeated query
 * parameter arrives as an array and a single one as a string; the handler normalises.
 */
export const DeleteProjectQuery = t.Object({
	cascade: t.Optional(t.Literal('clients')),
	client: t.Optional(t.Union([t.String(), t.Array(t.String())]))
});
