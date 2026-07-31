import type { ModelAreaName } from '../consts/storage_inventory.js';
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
import type {
	VerificationChallengePayload,
	VerificationResendPayload
} from '../verification/types.js';

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
	VerificationChallenge: VerificationChallengePayload;
	VerificationResend: VerificationResendPayload;
}

/*
 * Derived from the provisioning inventory's runtime tuple rather than from `keyof
 * ModelPayloadByName`, so the set of model areas has exactly one definition. The direction matters:
 * a type erases at runtime, and the drift guard that keeps provisioning honest can only compare
 * values — so the tuple is the source and this is the derivation.
 */
export type KnownModelName = ModelAreaName;

/*
 * Ties the payload map to that tuple in both directions. A model area with no payload type, or a
 * payload type for an area no longer in the inventory, makes one of these non-`never` and fails to
 * compile. A secondary net only — `bun run typecheck` is red repo-wide, so it gates nothing today;
 * test/storage_contract/inventory_drift.spec.ts is the enforcement that runs.
 */
type PayloadTypesMissingFromMap = Exclude<
	ModelAreaName,
	keyof ModelPayloadByName
>;
type PayloadTypesNotInInventory = Exclude<
	keyof ModelPayloadByName,
	ModelAreaName
>;
export type ModelPayloadMapMatchesInventory = [
	PayloadTypesMissingFromMap,
	PayloadTypesNotInInventory
] extends [never, never]
	? true
	: never;

/*
 * Indexed by `keyof ModelPayloadByName` rather than by KnownModelName so the lookup stays provably
 * valid to the compiler; the assertion above is what guarantees the two key sets are the same.
 */
export type PayloadForModel<TModelName extends string> =
	TModelName extends keyof ModelPayloadByName
		? ModelPayloadByName[TModelName]
		: Record<string, unknown>;
