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

export const SetBucketBody = t.Object({
	bucketId: t.String()
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
