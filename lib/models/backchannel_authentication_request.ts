import { Type as t, type Static } from '@sinclair/typebox';
import {
	BaseToken,
	BaseTokenPayload,
	SessionBoundPayload
} from './base_token.js';
import consumable, { ConsumedPayload } from './mixins/consumable.ts';
import { authPayloadModel } from './mixins/stores_auth.js';
import { StoredParams } from './stored_params.ts';
import { ttl } from '../configs/liveTime.js';

export const BackchannelAuthenticationRequestPayload = t.Object({
	...BaseTokenPayload.properties,
	...SessionBoundPayload.properties,
	...authPayloadModel.properties,
	consumed: ConsumedPayload,
	error: t.Optional(t.String()),
	errorDescription: t.Optional(t.String()),
	params: t.Optional(StoredParams)
});
export type BackchannelAuthenticationRequestPayloadType = Static<
	typeof BackchannelAuthenticationRequestPayload
>;

export class BackchannelAuthenticationRequest extends consumable(
	BaseToken<BackchannelAuthenticationRequestPayloadType>
) {
	declare payload: Omit<BackchannelAuthenticationRequestPayloadType, 'kind'> & {
		kind: string;
	};
	model = BackchannelAuthenticationRequestPayload;
	static isSessionBound = true;

	get expiration(): number {
		return (this.expiresIn ||= ttl.BackchannelAuthenticationRequest(
			this,
			this.client
		));
	}
}
