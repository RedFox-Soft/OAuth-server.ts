import { t } from 'elysia';

import {
	BUCKET_SLUG_MAX_LENGTH,
	BUCKET_SLUG_PATTERN
} from '../../consts/reserved_names.js';

const VerificationMethod = t.Union([t.Literal('link'), t.Literal('code')]);

/*
 * `passwordLogin` is here; `federation` deliberately is not. Providers are reachable only through their own
 * routes, so a bucket PATCH cannot replace a set of upstream secrets in a request whose audit entry would
 * say only `federation` — and write-time issuer validation keeps a single choke point.
 */
/*
 * The bucket's address, distinct from `name` beside it: `name` is the display name an operator reads
 * in a list ("Default users"), `slug` is the path segment its endpoints live beneath and the path
 * component of its issuer identifier. The shape rules live in `lib/consts/reserved_names.ts` so this
 * schema and the router share one declaration; the route adds what a pattern cannot check — that the
 * slug is not reserved and not already taken.
 */
const BucketSlug = t.String({
	pattern: BUCKET_SLUG_PATTERN,
	maxLength: BUCKET_SLUG_MAX_LENGTH
});

export const CreateBucketBody = t.Object({
	name: t.String({ minLength: 1 }),
	slug: BucketSlug,
	roles: t.Optional(t.Array(t.String())),
	passwordLogin: t.Optional(t.Boolean()),
	registrationOpen: t.Optional(t.Boolean()),
	emailVerificationRequired: t.Optional(t.Boolean()),
	verificationMethod: t.Optional(VerificationMethod),
	totpRequired: t.Optional(t.Boolean())
});

export const UpdateBucketBody = t.Object({
	name: t.Optional(t.String({ minLength: 1 })),
	/*
	 * `slug` is deliberately absent, so a bucket's address is fixed once chosen.
	 *
	 * Not because changing it is unthinkable — an operator can mistype one — but because it is not an
	 * ordinary edit and this body is where ordinary edits live. Changing a slug changes the bucket's
	 * issuer identifier, so every client integrated with it stops validating tokens on the next
	 * request; for the administrators bucket it also moves the issuer the admin console authenticates
	 * against, locking operators out of the surface that could move it back.
	 *
	 * Admitting it here would grant that consequence the same weight as renaming a display name: one
	 * audit action for both, and on the agent-facing surface one `ordinary` classification covering
	 * both, so the two-call confirmation gate would never see it. Raising this whole operation to
	 * `high` instead would gate every flag and label change behind a confirmation, which is the wrong
	 * trade in the other direction.
	 *
	 * The right shape is a rename operation of its own — its own route, its own audit action, its own
	 * `high` classification — and that is a feature rather than a field. Until it exists, an address is
	 * chosen once.
	 */
	roles: t.Optional(t.Array(t.String())),
	passwordLogin: t.Optional(t.Boolean()),
	registrationOpen: t.Optional(t.Boolean()),
	emailVerificationRequired: t.Optional(t.Boolean()),
	verificationMethod: t.Optional(VerificationMethod),
	/*
	 * Governs the password door only — a federated sign-in is never gated by it, because the upstream
	 * provider owns its own factor policy. Accepted while `passwordLogin` is off, where it is inert;
	 * the route says so rather than refusing.
	 */
	totpRequired: t.Optional(t.Boolean())
});
