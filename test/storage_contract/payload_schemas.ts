/*
 * The runtime payload schema for every model area, for the ownership drift guard to read.
 *
 * Test-only on purpose. lib/adapters/modelTypes.ts already maps every area to its payload *type*, but
 * with `import type` — so it erases, and turning those into value imports would drag the whole model
 * graph into every adapter consumer. A test-only map carries no production weight, and the key-set
 * assertion in inventory_drift.spec.ts is what stops it drifting: an area added without a schema here
 * fails the suite.
 *
 * The `test_helper` import must stay first. Entering the model graph at `lib/models/access_token.ts`
 * cold throws `ReferenceError: Cannot access 'BaseTokenPayload' before initialization` — base_token
 * reaches grant.ts through its own import chain, and grant.ts composes BaseTokenPayload while
 * base_token is still evaluating. test_helper enters the graph in an order that resolves.
 */
import '../test_helper.js';

import { AccessTokenPayload } from 'lib/models/access_token.js';
import { AuthorizationCodePayload } from 'lib/models/authorization_code.js';
import { BackchannelAuthenticationRequestPayload } from 'lib/models/backchannel_authentication_request.js';
import { ClientCredentialsPayload } from 'lib/models/client_credentials.js';
import { DeviceCodePayload } from 'lib/models/device_code.js';
import { FederationStatePayload } from 'lib/federation/types.js';
import { GrantPayload } from 'lib/models/grant.js';
import { InitialAccessTokenPayload } from 'lib/models/initial_access_token.js';
import { InteractionPayload } from 'lib/models/interaction.js';
import {
	PasswordResetChallengePayload,
	PasswordResetThrottlePayload
} from 'lib/password_reset/types.js';
import { PushedAuthorizationRequestPayload } from 'lib/models/pushed_authorization_request.js';
import { RefreshTokenSchema } from 'lib/models/refresh_token.js';
import { RegistrationAccessTokenPayload } from 'lib/models/registration_access_token.js';
import { ReplayDetectionPayload } from 'lib/models/replay_detection.js';
import { SessionPayload } from 'lib/models/session.js';
import {
	VerificationChallengePayload,
	VerificationResendPayload
} from 'lib/verification/types.js';

export interface ReadableSchema {
	readonly properties: Record<string, unknown>;
}

export const PAYLOAD_SCHEMAS: Readonly<Record<string, ReadableSchema>> = {
	AccessToken: AccessTokenPayload,
	AuthorizationCode: AuthorizationCodePayload,
	BackchannelAuthenticationRequest: BackchannelAuthenticationRequestPayload,
	ClientCredentials: ClientCredentialsPayload,
	DeviceCode: DeviceCodePayload,
	FederationState: FederationStatePayload,
	Grant: GrantPayload,
	InitialAccessToken: InitialAccessTokenPayload,
	Interaction: InteractionPayload,
	PasswordResetChallenge: PasswordResetChallengePayload,
	PasswordResetThrottle: PasswordResetThrottlePayload,
	PushedAuthorizationRequest: PushedAuthorizationRequestPayload,
	RefreshToken: RefreshTokenSchema,
	RegistrationAccessToken: RegistrationAccessTokenPayload,
	ReplayDetection: ReplayDetectionPayload,
	Session: SessionPayload,
	VerificationChallenge: VerificationChallengePayload,
	VerificationResend: VerificationResendPayload
};

/*
 * `Client` is the one area with no payload schema in the model sense — ModelPayloadByName types it as
 * `Record<string, unknown>` and the façade in lib/models/client.ts carries no `model` field. It is also
 * the one area the reverse check must not run against: lib/configs/clientSchema.ts declares a
 * `clientId`, but that is the client's own identity, not a pointer to an owning principal, so an
 * unexempted check would flag it forever.
 */
export const SCHEMA_EXEMPT_AREAS: ReadonlySet<string> = new Set(['Client']);

/* The two fields the guard treats as ownership pointers wherever they appear. */
export const OWNER_FIELDS = ['accountId', 'clientId'] as const;
