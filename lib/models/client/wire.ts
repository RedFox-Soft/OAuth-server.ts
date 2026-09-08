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

type Body = Record<string, unknown>;

/*
 * Both directions build a new object rather than editing one in place. The mutating form these
 * replaced returned its argument too, so a call site could ignore the result and still see the
 * change — which made "does this function move keys or copy them" unanswerable from the call site,
 * and left every caller sharing one object with whoever handed it over.
 */
function translate(source: Body, direction: 'toCanonical' | 'toSnake'): Body {
	const lookup = new Map(
		Object.entries(CLIENT_METADATA_WIRE_MAP).map(([snake, canonical]) =>
			direction === 'toCanonical' ? [snake, canonical] : [canonical, snake]
		)
	);

	const out: Body = {};
	for (const [key, value] of Object.entries(source)) {
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
