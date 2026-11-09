import EventEmitter from 'node:events';

/*
 * eventBus
 *
 * The server's lifecycle events: the actions emit here, deployments subscribe. That is the entire
 * contract, so a bare EventEmitter is the entire implementation — there is no init step, no
 * construction step and nothing to configure. Settings live on ApplicationConfig (validated where
 * they are loaded, in configs/application.ts), on ClientDefaults, or in the addon registry; signing
 * keys are records in the key store (lib/keys/issuer_keys.ts). None of it is an input to this module.
 *
 * It was called `provider` until it stopped being one — inherited from oidc-provider, where a
 * Provider instance owned the configuration, the routes, the model classes and the keys, and was
 * constructed per deployment. Every one of those responsibilities now lives with the module that
 * implements it, and what remained of the class was the event emitter it extended.
 *
 * Importing no model is load-bearing. This module used to need an explicit
 * `import './models/id_token.js'` anchor, because it pulled in Client and Grant for
 * backchannelResult — which made it a participant in the base_token -> base_model -> this module
 * cycle, and entering that cycle here left base_token half-initialised (grant.ts threw "Cannot
 * access 'BaseTokenPayload' before initialization"). Moving backchannelResult to
 * actions/authorization/backchannel_result.ts made this a leaf, so base_model -> here terminates and
 * the anchor is gone. Keep it that way.
 *
 * The event map below imports types only, which the compiler erases, so it adds no runtime edge and
 * the module stays a leaf. It is the contract a subscriber codes against: an event name the server
 * does not emit, or a listener expecting arguments it does not pass, is a compile error rather than a
 * handler that silently never runs or reads `undefined`.
 */
import type { OIDCContext } from './helpers/oidc_context.ts';
import type {
	Outcome as BehindProxyOutcome,
	Reason as BehindProxyReason
} from './behind_proxy/decide.ts';
import type { ApiReason as BehindProxyApiReason } from './behind_proxy/answers.ts';
import type { Client } from './models/client.ts';
import type { AccessToken } from './models/access_token.ts';
import type { AuthorizationCode } from './models/authorization_code.ts';
import type { BackchannelAuthenticationRequest } from './models/backchannel_authentication_request.ts';
import type { ClientCredentials } from './models/client_credentials.ts';
import type { DeviceCode } from './models/device_code.ts';
import type { Grant } from './models/grant.ts';
import type { InitialAccessToken } from './models/initial_access_token.ts';
import type { Interaction } from './models/interaction.ts';
import type { PushedAuthorizationRequest } from './models/pushed_authorization_request.ts';
import type { RefreshToken } from './models/refresh_token.ts';
import type { RegistrationAccessToken } from './models/registration_access_token.ts';
import type { ReplayDetection } from './models/replay_detection.ts';
import type { Session } from './models/session.ts';
import type { StartedPrompt } from './actions/authorization/interactions.ts';
import type {
	ConnectedAccountBreak,
	ConnectedAccountVia
} from './connected_services/types.ts';

/* BaseModel.emit names an event `${snake_case(class name)}.${lifecycle}` and passes the instance. */
interface ModelEventSubjects {
	access_token: AccessToken;
	authorization_code: AuthorizationCode;
	backchannel_authentication_request: BackchannelAuthenticationRequest;
	client_credentials: ClientCredentials;
	device_code: DeviceCode;
	grant: Grant;
	initial_access_token: InitialAccessToken;
	interaction: Interaction;
	pushed_authorization_request: PushedAuthorizationRequest;
	refresh_token: RefreshToken;
	registration_access_token: RegistrationAccessToken;
	replay_detection: ReplayDetection;
	session: Session;
}
export type ModelLifecycle = 'saved' | 'issued' | 'destroyed' | 'consumed';
export type ModelEventName = `${keyof ModelEventSubjects}.${ModelLifecycle}`;

/* The shared onError files a refusal under its endpoint's name (authorization_error_handler.ts). */
export type EndpointErrorEvent =
	| 'grant.error'
	| 'pushed_authorization_request.error'
	| 'authorization.error'
	| 'device_authorization.error'
	| 'backchannel_authentication.error'
	| 'introspection.error'
	| 'userinfo.error'
	| 'end_session.error'
	| 'end_session_confirm.error'
	| 'revocation.error'
	| 'global_token_revocation.error';

type ModelEvents = {
	[K in keyof ModelEventSubjects as `${K}.${ModelLifecycle}`]: [
		model: ModelEventSubjects[K]
	];
};
type EndpointErrors = { [K in EndpointErrorEvent]: [error: Error] };

// Any endpoint's context: each one types its own parameters, and a subscriber reads them as unknown.
type RequestContext = OIDCContext<Record<string, unknown>>;

/*
 * A request-scoped event carries the request context first; where the same event can also happen with
 * no protocol request behind it, that position is `undefined` (wiki/entities/event-bus.md).
 */
export type ServerEvents = ModelEvents &
	EndpointErrors & {
		server_error: [error: unknown];
		'assign.client': [oidc: RequestContext, client: Client | undefined];
		'authorization.accepted': [oidc: RequestContext];
		'authorization.success': [
			oidc: RequestContext,
			response?: Awaited<
				ReturnType<typeof import('./helpers/process_response_types.ts').default>
			>
		];
		'interaction.started': [oidc: RequestContext, prompt: StartedPrompt];
		'interaction.ended': [oidc: RequestContext];
		'grant.success': [oidc: RequestContext];
		'grant.revoked': [oidc: RequestContext | undefined, grantId: string];
		'end_session.success': [oidc: RequestContext];
		'device_authorization.success': [
			oidc: RequestContext,
			response: Awaited<
				ReturnType<
					typeof import('./actions/authorization/device_authorization_response.ts').default
				>
			>
		];
		'pushed_authorization_request.success': [
			oidc: RequestContext,
			client: Client
		];
		'registration_create.success': [oidc: RequestContext, client: Client];
		'registration_update.success': [oidc: RequestContext, client: Client];
		'registration_delete.success': [oidc: RequestContext, client: Client];
		'code_verification.error': [oidc: RequestContext, error: unknown];
		'backchannel.success': [
			oidc: RequestContext | undefined,
			client: Client,
			accountId: string | undefined,
			sid: string | undefined
		];
		'backchannel.error': [
			oidc: RequestContext | undefined,
			error: unknown,
			client: Client,
			accountId: string | undefined,
			sid: string | undefined
		];
		feature_disabled: [{ method: string; path: string; flag: string }];
		rate_limited: [
			{ method: string; path: string; class: string; origin: string }
		];
		login_throttled: [{ bucketId: string }];
		/* A password sign-in refused because of FoxTrust's attacker list (specs/125); never the address. */
		password_guessing_refused: [{ bucketId: string }];
		settings_applied: [{ keys: readonly string[] }];
		'admin.login.error': [{ reason: string }];
		'federation.link.conflict': [{ providerId: string; connectionId: string }];
		'federation.upstream.error': [{ providerId: string; reason: string }];
		'federation.idtoken.error': [{ providerId: string; reason: string }];
		/* A linked sign-in the provider refused for the service's scopes, sent again without them (specs/120 R10). */
		'federation.keep.retried': [{ providerId: string; error: string }];
		'mcp.auth.error': [{ reason: string }];
		'provisioning.held': [
			{ bucketId: string; connectionId: string; count: number }
		];
		'provisioning.held.refused': [
			{
				bucketId: string;
				connectionId: string;
				userId: string;
				operation: 'deactivate' | 'delete';
				/* Present when the refusal could not be recorded; the 429 was answered regardless. */
				failed?: true;
			}
		];
		'provisioning.hold.alert_failed': [
			{ bucketId: string; connectionId: string; reason: string }
		];
		'scim.auth.refused': [{ bucketId: string; reason: string }];
		'upstream.logout.success': [
			{ bucketId: string; providerId: string; ended: number }
		];
		'upstream.logout.refused': [
			{ bucketId: string; providerId?: string; reason: string }
		];
		'upstream.revocation.success': [
			{ bucketId: string; providerId: string; accountId: string }
		];
		'upstream.revocation.refused': [{ bucketId: string; reason: string }];
		/*
		 * Connected accounts (specs/117 R11). Identifiers only: never a token, and never the upstream label, which
		 * is personal data the audit trail already holds.
		 */
		'connected_account.connected': [
			ConnectedAccountEvent & { via?: ConnectedAccountVia }
		];
		'connected_account.updated': [
			ConnectedAccountEvent & { via?: ConnectedAccountVia }
		];
		'connected_account.deleted': [
			ConnectedAccountEvent & { by: 'person' | 'administrator' | 'cascade' }
		];
		'connected_account.revocation': [
			ConnectedAccountEvent & { outcome: RevocationOutcome }
		];
		'connected_account.refused': [
			{ bucketId: string; serviceId?: string; reason: string }
		];
		/*
		 * An agent obtained the upstream token (specs/118 R15). `clientId` is the agent the person consented to;
		 * `exchangedBy` the application that asked, the same one unless an API's exchanging application did.
		 */
		'connected_account.exchanged': [
			ConnectedAccountEvent & { clientId: string; exchangedBy: string }
		];
		'connected_account.refreshed': [
			ConnectedAccountEvent & {
				trigger: 'exchange' | 'keep_alive' | 'revocation';
			}
		];
		'connected_account.broken': [
			ConnectedAccountEvent & { reason: ConnectedAccountBreak }
		];
		'connected_account.consent': [
			ConnectedAccountEvent & {
				clientId: string;
				change: 'allowed' | 'declined' | 'withdrawn';
				via: 'consent_screen' | 'account_page' | 'connect_link';
			}
		];
		/*
		 * An agent's connect link (specs/119 R8), named by its public id: never its value, a token or a label.
		 * `refused` is the link's own person check or recheck, never an unknown value, which identifies nothing.
		 */
		'connect_link.issued': [ConnectLinkEvent];
		'connect_link.completed': [
			ConnectLinkEvent & { connectedAccountId: string }
		];
		'connect_link.declined': [ConnectLinkEvent];
		'connect_link.refused': [
			{
				bucketId: string;
				serviceId: string;
				connectId: string;
				cause: 'other_person' | 'changed';
			}
		];
		/*
		 * A check a proxy made for an app behind it (specs/122 R16), once its app is known. Identifiers only: never
		 * the forwarded host, path or a cookie. `rule` is the path of the rule that decided, or null.
		 */
		'behind_proxy.decision': [
			{
				bucketId: string;
				appId: string;
				outcome: BehindProxyOutcome;
				reason: BehindProxyReason;
				rule: string | null;
				accountId: string | null;
			}
		];
		/*
		 * A check a proxy made for an API whose tokens it checks (specs/123 R15), once the API is known and the
		 * request is for its host. Identifiers only: never the token or a forwarded header. `tool` is the decoded
		 * `Mcp-Name` of a tool call, or null.
		 */
		'behind_proxy.api_decision': [
			{
				bucketId: string;
				resource: string;
				outcome: 'allow' | 'refuse';
				reason: BehindProxyApiReason;
				tool: string | null;
				clientId: string | null;
			}
		];
	};

interface ConnectLinkEvent {
	bucketId: string;
	accountId: string;
	clientId: string;
	exchangedBy: string;
	serviceId: string;
	act: 'connect' | 'consent' | 'reconnect';
	connectId: string;
}

interface ConnectedAccountEvent {
	bucketId: string;
	serviceId: string;
	connectedAccountId: string;
	accountId: string;
}

/* What asking a provider to revoke came to; `unreadable` means the token could not be opened to send. */
export type RevocationOutcome =
	'revoked' | 'not_supported' | 'failed' | 'unreadable';

export type ServerEventName = keyof ServerEvents;

/* A listener for one event, or for several: with a union of names it accepts any of their arguments. */
export type ServerListener<K extends ServerEventName> = (
	...args: ServerEvents[K]
) => void;

export const eventBus = new EventEmitter<ServerEvents>();
