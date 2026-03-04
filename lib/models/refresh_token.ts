import { Type as t, type Static } from '@sinclair/typebox';
import epochTime from '../helpers/epoch_time.js';
import { BaseToken, BaseTokenPayload } from './base_token.js';

import consumable from './mixins/consumable.js';
import constrained from './mixins/is_sender_constrained.js';
import { authPayloadModel } from './mixins/stores_auth.js';

const RefreshTokenSchema = t.Composite([
	BaseTokenPayload,
	authPayloadModel,
	t.Object({
		iiat: t.Number(),
		gty: t.String(),
		rar: t.Optional(t.Unknown()),
		rotations: t.Optional(t.Number()),
		consumed: t.Boolean(),
		'x5t#S256': t.Optional(t.String()),
		jkt: t.Optional(t.String())
	})
]);

type RefreshTokenPayload = Static<typeof RefreshTokenSchema>;

export class RefreshToken extends consumable<RefreshTokenPayload>(
	constrained<RefreshTokenPayload>(BaseToken)
) {
	model = RefreshTokenSchema;
	static isSessionBound = true;

	constructor(payload: RefreshTokenPayload) {
		super(payload);
		if (!this.payload.iiat) {
			this.payload.iiat = this.payload.iat || epochTime();
		}
	}

	/*
	 * totalLifetime()
	 * number of seconds since the very first refresh token chain iat
	 */
	totalLifetime() {
		return epochTime() - this.payload.iiat;
	}
}
