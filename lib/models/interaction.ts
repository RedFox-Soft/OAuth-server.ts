import { Type as t, type Static } from '@sinclair/typebox';
import epochTime from '../helpers/epoch_time.js';
import { BaseModel, BaseModelPayload } from './base_model.js';
import type { InteractionResult } from '../helpers/oidc_context.ts';
import { StoredParams } from './stored_params.ts';
import type { Grant } from './grant.ts';
import type { Session } from './session.ts';

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
	/*
	 * An upstream identity whose address matched an account holding only a password. Linked when this
	 * interaction's sign-in completes as that account, and dropped when it completes as any other — the
	 * assertion proved control of the address, not of whoever set the password. Declared inline rather
	 * than imported from lib/federation/types.ts, which would put the federation graph in every model's.
	 */
	pendingLink: t.Optional(
		t.Object({
			accountId: t.String(),
			bucketId: t.String(),
			providerId: t.String(),
			sub: t.String(),
			claims: t.Optional(t.Record(t.String(), t.Unknown())),
			/* Declared here as well as in lib/federation/types.ts: undeclared, it would be dropped on persist. */
			sid: t.Optional(t.String())
		})
	),
	result: t.Optional(Outcome)
});
export type InteractionPayloadType = Static<typeof InteractionPayload>;

/*
 * What a new interaction is made from: its payload, where `session` and `grant` may still be the live
 * models, which the constructor reduces to what the record stores. The models are imported as types
 * only, which are erased, so this adds no edge to the model graph (wiki: model-graph-import-order).
 */
type InteractionInit = Record<string, unknown> & {
	session?: Session | InteractionPayloadType['session'];
	grant?: Grant;
};

// The part of a session an interaction keeps; a session nobody has signed in to keeps none.
function storedSession(session: Session): InteractionPayloadType['session'] {
	const { accountId, uid, jti, acr, amr } = session.payload;
	if (!accountId) return undefined;
	return {
		accountId,
		...(uid ? { uid } : undefined),
		...(jti ? { cookie: jti } : undefined),
		...(acr ? { acr } : undefined),
		...(amr ? { amr } : undefined)
	};
}

export class Interaction extends BaseModel<InteractionPayloadType> {
	static schema = InteractionPayload;

	// Read back from storage, the stored payload alone (that is how tryFind builds one); new, an id and a payload.
	constructor(payload: InteractionPayloadType);
	constructor(jti: string, payload: InteractionInit);
	constructor(jti: string | InteractionPayloadType, payload?: InteractionInit) {
		if (typeof jti === 'string' && payload) {
			const { session, grant, ...rest } = payload;
			super({
				jti,
				...rest,
				session:
					session instanceof BaseModel ? storedSession(session) : session,
				...(grant?.id ? { grantId: grant.id } : undefined)
			});
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
