import type { AccessTokenPayloadType } from '../models/access_token.js';
import type { AuthorizationCodePayloadType } from '../models/authorization_code.js';
import type { BackchannelAuthenticationRequestPayloadType } from '../models/backchannel_authentication_request.js';
import type { ClientCredentialsPayload } from '../models/client_credentials.js';
import type { DeviceCodePayloadType } from '../models/device_code.js';
import type { GrantPayloadType } from '../models/grant.js';
import type { InitialAccessTokenPayloadType } from '../models/initial_access_token.js';
import type { InteractionPayloadType } from '../models/interaction.js';
import type { PushedAuthorizationRequestPayloadType } from '../models/pushed_authorization_request.js';
import type { RefreshTokenPayload } from '../models/refresh_token.js';
import type { RegistrationAccessTokenPayloadType } from '../models/registration_access_token.js';
import type { ReplayDetectionPayloadType } from '../models/replay_detection.js';
import type { SessionPayloadType } from '../models/session.js';

export type { AccessTokenPayloadType } from '../models/access_token.js';
export type { AuthorizationCodePayloadType } from '../models/authorization_code.js';
export type { BackchannelAuthenticationRequestPayloadType } from '../models/backchannel_authentication_request.js';
export type { BaseModelPayloadType } from '../models/base_model.js';
export type { BaseTokenPayloadType } from '../models/base_token.js';
export type { ClientCredentialsPayload } from '../models/client_credentials.js';
export type { DeviceCodePayloadType } from '../models/device_code.js';
export type { GrantPayloadType } from '../models/grant.js';
export type { InitialAccessTokenPayloadType } from '../models/initial_access_token.js';
export type { InteractionPayloadType } from '../models/interaction.js';
export type { PushedAuthorizationRequestPayloadType } from '../models/pushed_authorization_request.js';
export type { RefreshTokenPayload } from '../models/refresh_token.js';
export type { RegistrationAccessTokenPayloadType } from '../models/registration_access_token.js';
export type { ReplayDetectionPayloadType } from '../models/replay_detection.js';
export type { SessionPayloadType } from '../models/session.js';

export interface ModelPayloadByName {
	AccessToken: AccessTokenPayloadType;
	AuthorizationCode: AuthorizationCodePayloadType;
	BackchannelAuthenticationRequest: BackchannelAuthenticationRequestPayloadType;
	Client: Record<string, unknown>;
	ClientCredentials: ClientCredentialsPayload;
	DeviceCode: DeviceCodePayloadType;
	Grant: GrantPayloadType;
	InitialAccessToken: InitialAccessTokenPayloadType;
	Interaction: InteractionPayloadType;
	PushedAuthorizationRequest: PushedAuthorizationRequestPayloadType;
	RefreshToken: RefreshTokenPayload;
	RegistrationAccessToken: RegistrationAccessTokenPayloadType;
	ReplayDetection: ReplayDetectionPayloadType;
	Session: SessionPayloadType;
}

export type KnownModelName = keyof ModelPayloadByName;

export type PayloadForModel<TModelName extends string> =
	TModelName extends KnownModelName
		? ModelPayloadByName[TModelName]
		: Record<string, unknown>;
