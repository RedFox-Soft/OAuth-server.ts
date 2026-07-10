import { Type as t, type Static } from '@sinclair/typebox';
import epochTime from '../helpers/epoch_time.js';
import { BaseModel, BaseModelPayload } from './base_model.js';

// Interaction persists a freeform interaction record. Freeform sub-objects (prompt, params,
// result, lastSubmission) are declared as t.Unknown() so the shallow projection copies them
// verbatim and Value.Check accepts every real shape on both save and reload. `session` is an open
// object because the constructor reduces the Session model to a plain subset. `grant` is
// deliberately NOT declared: the constructor derives `grantId` from the Grant instance and nothing
// reads the instance back, so filtering drops it rather than persisting a live model instance.
const InteractionPayload = t.Composite([
	BaseModelPayload,
	t.Object({
		returnTo: t.Optional(t.String()),
		prompt: t.Optional(t.Unknown()),
		cookieID: t.Optional(t.String()),
		lastSubmission: t.Optional(t.Unknown()),
		accountId: t.Optional(t.String()),
		params: t.Optional(t.Unknown()),
		trusted: t.Optional(t.Unknown()),
		session: t.Optional(t.Object({}, { additionalProperties: true })),
		grantId: t.Optional(t.String()),
		cid: t.Optional(t.String()),
		deviceCode: t.Optional(t.String()),
		parJti: t.Optional(t.String()),
		result: t.Optional(t.Unknown())
	})
]);
export type InteractionPayloadType = Static<typeof InteractionPayload>;

export class Interaction extends BaseModel<InteractionPayloadType> {
	model = InteractionPayload;

	constructor(jti: string, payload: Record<string, unknown>) {
		if (arguments.length === 2) {
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
		} else {
			super(jti);
		}
	}

	get uid() {
		return this.jti;
	}

	set uid(value) {
		this.jti = value;
	}

	async save(ttl: number) {
		if (typeof ttl !== 'number') {
			throw new TypeError('"ttl" argument must be a number');
		}
		return super.save(ttl);
	}

	async persist() {
		if (typeof this.exp !== 'number') {
			throw new TypeError(
				'persist can only be called on previously persisted Interactions'
			);
		}
		return this.save(this.exp - epochTime());
	}
}
