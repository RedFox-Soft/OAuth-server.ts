/*
 * The one translation between the snake_case client metadata that travels on the wire and the
 * canonical camelCase/dotted keys the client model uses internally.
 *
 * RFC 7591/7592 and the Client ID Metadata Document draft both speak snake_case; the model keeps the
 * base registration attributes as canonical names, and they are deliberately NOT in
 * RECOGNIZED_METADATA — so the schema engine neither reads them from snake input nor snakes them back
 * out. Everything in RECOGNIZED_METADATA already round-trips through the schema and is therefore
 * absent from the map below.
 *
 * Extracted from `lib/actions/registration.ts` when a second wire format came to need it. Shared
 * rather than copied: two maps would drift, and the failure mode of a drifted entry is a metadata
 * field silently ignored — accepted on the wire and absent from the client.
 *
 * Imports nothing, so it is reachable from the client resolution path without dragging an action
 * module (and from there the adapters) behind it.
 */
export const CLIENT_METADATA_WIRE_MAP = {
	client_id: 'clientId',
	client_secret: 'clientSecret',
	redirect_uris: 'redirectUris',
	application_type: 'applicationType',
	response_types: 'responseTypes',
	response_modes: 'responseModes',
	grant_types: 'grantTypes',
	subject_type: 'subjectType',
	request_object_signing_alg: 'requestObject.signingAlg',
	backchannel_authentication_request_signing_alg:
		'requestObject.backChannelSigningAlg'
} as const;

/*
 * The base registration keys the client model copies verbatim from a record. Frozen so expanding
 * `ClientSchema` to describe the full validated-object type (the rest of the metadata is produced by
 * the schema engine and camelCased) cannot change which keys are picked.
 *
 * Declared here rather than beside the validator because they are also what wire input must never
 * carry. Every one of them is a canonical name, never a wire name, so a registration body or a client
 * document that spells one is naming the model's internals — and was once believed: `clientId` after
 * the server's own `client_id` overwrote any stored client, and `consent.require: false` switched off
 * the consent screen for a self-registered one.
 */
export const BASE_METADATA_KEYS = [
	'clientId',
	'clientSecret',
	'redirectUris',
	'applicationType',
	'responseTypes',
	'responseModes',
	'grantTypes',
	'subjectType',
	'authorization.requirePushedAuthorizationRequests',
	'requestObject.require',
	'requestObject.signingAlg',
	'requestObject.backChannelSigningAlg',
	'consent.require',
	/*
	 * Whether the server created this client on its own request. A base key rather than recognised
	 * metadata: it is not something a client may send — `lib/actions/registration.ts` sets it after the
	 * wire translation — and it must survive the round trip through storage, which only keeps what is
	 * picked by the validator.
	 */
	'registeredDynamically',
	'registeredAtBucket',
	'registrationUsedAt',
	/*
	 * A provisioning connection's client, synthesized from the connection and never stored
	 * (lib/provisioning/client.ts). Base keys for the reason the three above are: no wire input may claim
	 * to be a connection's client or present a digest in place of a secret.
	 */
	'provisioningConnectionId',
	'clientSecretDigest'
];

const CANONICAL_ONLY = new Set(BASE_METADATA_KEYS);

type Body = Record<string, unknown>;

/*
 * Both directions build a new object rather than editing one in place. The mutating form these
 * replaced returned its argument too, so a call site could ignore the result and still see the
 * change — which made "does this function move keys or copy them" unanswerable from the call site,
 * and left every caller sharing one object with whoever handed it over.
 *
 * Towards canonical, a key that is already canonical is dropped rather than passed through: the source
 * is wire input written by the caller, and only the server may speak for the model's base attributes.
 * Dropped rather than refused, as RFC 7591 §2 has a server ignore metadata it does not understand.
 */
function translate(source: Body, direction: 'toCanonical' | 'toSnake'): Body {
	const lookup = new Map(
		Object.entries(CLIENT_METADATA_WIRE_MAP).map(([snake, canonical]) =>
			direction === 'toCanonical' ? [snake, canonical] : [canonical, snake]
		)
	);

	const out: Body = {};
	for (const [key, value] of Object.entries(source)) {
		if (direction === 'toCanonical' && CANONICAL_ONLY.has(key)) {
			continue;
		}
		out[lookup.get(key) ?? key] = value;
	}
	return out;
}

export function snakeToCanonical(body: Body): Body {
	return translate(body, 'toCanonical');
}

export function canonicalToSnake(metadata: Body): Body {
	return translate(metadata, 'toSnake');
}
