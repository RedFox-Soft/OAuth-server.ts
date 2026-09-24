import { Type as t, type Static } from '@sinclair/typebox';
import epochTime from '../helpers/epoch_time.js';
import { BaseModel, BaseModelPayload } from './base_model.js';
import type { InteractionResult } from '../helpers/oidc_context.ts';
import { StoredParams } from './stored_params.ts';

/*
 * The outcome the interaction screens record. Like the stored parameters, it is copied verbatim on save
 * and never re-validated, so the schema states the writers' type rather than checks it.
 */
const Outcome = t.Unsafe<InteractionResult>(t.Record(t.String(), t.Unknown()));

// The prompt the policy stopped at (lib/actions/authorization/interactions.ts); `details` carries the
// consent checks' findings and whatever a deployment's own checks add.
const PendingPrompt = t.Object({
	name: t.String(),
	reasons: t.Array(t.String()),
	details: t.Object(
		{
			missingOIDCScope: t.Optional(t.Array(t.String())),
			missingOIDCClaims: t.Optional(t.Array(t.String())),
			missingResourceScopes: t.Optional(
				t.Record(t.String(), t.Array(t.String()))
			),
			rar: t.Optional(t.Array(t.Unknown()))
		},
		{ additionalProperties: true }
	)
});

// `session` is the subset of the Session model the constructor reduces it to. `grant` is deliberately
// NOT declared: the constructor derives `grantId` from the Grant instance and nothing reads the
// instance back, so filtering drops it rather than persisting a live model instance.
export const InteractionPayload = t.Object({
	...BaseModelPayload.properties,
	prompt: t.Optional(PendingPrompt),
	cookieID: t.Optional(t.String()),
	lastSubmission: t.Optional(Outcome),
	accountId: t.Optional(t.String()),
	params: t.Optional(StoredParams),
	trusted: t.Optional(t.Array(t.String())),
	session: t.Optional(
		t.Object(
			{
				accountId: t.String(),
				uid: t.Optional(t.String()),
				cookie: t.Optional(t.String()),
				acr: t.Optional(t.String()),
				amr: t.Optional(t.Array(t.String()))
			},
			{ additionalProperties: true }
		)
	),
	grantId: t.Optional(t.String()),
	deviceCode: t.Optional(t.String()),
	parJti: t.Optional(t.String()),
	/*
	 * The bucket whose address this interaction began at.
	 *
	 * Recorded so the interaction can only be completed there. Before buckets had hostnames this needed
	 * nothing: every interaction was served from one origin, so carrying a uid "elsewhere" meant editing
	 * a path prefix nothing read. A bucket host makes it a real boundary, and the failure without it is
	 * quiet — the sign-in completes and writes a session cookie onto the origin the request arrived at,
	 * named for the bucket the interaction belonged to, so it completes and then does not exist.
	 *
	 * Optional because an interaction written before this field existed has none, and one that does is
	 * simply not checked — the guard degrades to the behaviour it replaced rather than stranding a
	 * sign-in that is already in flight during a deploy.
	 */
	bucketId: t.Optional(t.String()),
	/*
	 * A sign-in that has passed the password and not yet the second factor. Declared rather than
	 * folded into the freeform `lastSubmission`, because a state that gates authentication should be
	 * visible in the model instead of inferred from an unknown blob.
	 *
	 * Its presence is what stops the sign-in completing: the login POST writes this *instead of*
	 * `result` when the bucket requires a code, and only the code POST turns it into a `result`.
	 * Living on the interaction gives it the interaction's own TTL, so a half-finished sign-in
	 * expires with the attempt it belongs to and needs no expiry logic of its own.
	 */
	secondFactor: t.Optional(
		t.Object({
			accountId: t.String(),
			/* The "remember me" choice, carried across the code step so it is not lost. */
			transient: t.Optional(t.Boolean()),
			/* Wrong codes in this attempt. The per-account window lives in the TotpAttempt area. */
			attempts: t.Number()
		})
	),
	result: t.Optional(Outcome)
});
export type InteractionPayloadType = Static<typeof InteractionPayload>;

export class Interaction extends BaseModel<InteractionPayloadType> {
	model = InteractionPayload;

	// Read back from storage, the stored payload alone (that is how tryFind builds one); new, an id and a payload.
	constructor(payload: InteractionPayloadType);
	constructor(jti: string, payload: Record<string, unknown>);
	constructor(
		jti: string | InteractionPayloadType,
		payload?: Record<string, unknown>
	) {
		if (typeof jti === 'string' && payload) {
			if (payload.session instanceof BaseModel) {
				const { session } = payload;
				Object.assign(
					payload,
					session.payload.accountId
						? {
								session: {
									accountId: session.payload.accountId,
									...(session.payload.uid
										? { uid: session.payload.uid }
										: undefined),
									...(session.payload.jti
										? { cookie: session.payload.jti }
										: undefined),
									...(session.payload.acr
										? { acr: session.payload.acr }
										: undefined),
									...(session.payload.amr
										? { amr: session.payload.amr }
										: undefined)
								}
							}
						: { session: undefined }
				);
			}

			if (payload.grant instanceof BaseModel) {
				const { grant } = payload;
				if (grant.id) {
					Object.assign(payload, { grantId: grant.id });
				}
			}

			super({ jti, ...payload });
		} else if (typeof jti !== 'string') {
			super(jti);
		} else {
			throw new TypeError('a new interaction needs a payload');
		}
	}

	// Every interaction is created with its identifier (the constructor requires one).
	get uid(): string {
		return this.id;
	}

	set uid(value: string) {
		this.id = value;
	}

	/*
	 * Saved again without changing when it expires. Clamped, because both ends of the unclamped range
	 * write the wrong thing through MongoAdapter.upsert: a TTL of exactly 0 is falsy there, so no
	 * `expiresAt` is written and an interaction seconds from death is left non-expiring; a negative one
	 * back-dates `expiresAt` and kills the record mid-request. Both are reachable when the interaction
	 * expires between being read and being saved. One second is the floor lib/totp/verify.ts uses too.
	 */
	persist() {
		const remaining = (this.payload.exp ?? epochTime()) - epochTime();
		return this.save(Math.max(1, remaining));
	}

	async save(ttl: number) {
		if (typeof ttl !== 'number') {
			throw new TypeError('"ttl" argument must be a number');
		}
		return super.save(ttl);
	}
}
