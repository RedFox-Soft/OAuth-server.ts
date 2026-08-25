import { LOOPBACKS } from '../../consts/client_attributes.js';
import { type ClientSchemaType } from '../../configs/clientSchema.ts';

// Pure allowance predicates replacing the former Client instance methods.
// Each takes the validated plain client object first. Behaviour must match the
// former methods exactly (FR-009), including responseModeAllowed's
// "absent list ⇒ allowed" rule and postLogoutRedirectUriAllowed's URL-normalised
// comparison.

export function responseTypeAllowed(
	client: ClientSchemaType,
	type: string
): boolean {
	return client.responseTypes.includes(type);
}

export function responseModeAllowed(
	client: ClientSchemaType,
	responseMode: string
): boolean {
	return client.responseModes?.includes(responseMode) !== false;
}

export function grantTypeAllowed(
	client: ClientSchemaType,
	type: string
): boolean {
	return client.grantTypes.includes(type);
}

/*
 * Exact membership, plus the one liberty RFC 8252 §7.3 requires: a native client redirecting to a
 * loopback interface receives its code on an ephemeral port chosen when the request is made, not when
 * the client was registered, so the port is the single component that may differ. Everything else —
 * scheme, host, path, query — still has to match a registered URI exactly.
 *
 * Without this a native client cannot use this server at all unless it happens to bind the very port
 * it registered: `lib/admin/seed.ts` registers the reserved MCP agent on three loopback URIs and says
 * as much ("the port is unpredictable ... OAuth 2.1 allows a loopback port to vary"), and a real MCP
 * client was observed picking 3118, then 46937. Registration-time validation already knows this shape
 * — `lib/helpers/validateRedirectUri.ts` admits `http:` for a native client only on a LOOPBACKS host —
 * so this is the request-time half of a rule the codebase already half-implemented.
 *
 * Deliberately narrow, because widening redirect matching is how codes get stolen:
 *  - native clients only. A web client's redirect is a real host it controls; nothing about it is
 *    ephemeral, so there is no port to excuse.
 *  - `http:` only, and only on a loopback host. A claimed-https or private-scheme redirect names a
 *    host or scheme the client owns and stays exact.
 *  - hostnames are compared as written. `localhost` and `127.0.0.1` are not made interchangeable —
 *    the seed registers both forms rather than relying on the server to equate them.
 *
 * What remains open by design is a local port race: another process on the user's machine could bind
 * the port and receive the code. PKCE is what closes that, and it is mandatory for public clients
 * here, which is the same trade RFC 8252 §8.10 makes.
 */
export function redirectUriAllowed(
	client: ClientSchemaType,
	value: string
): boolean {
	if (client.redirectUris.includes(value)) {
		return true;
	}

	if (client.applicationType !== 'native') {
		return false;
	}

	const requested = URL.parse(value);
	if (
		!requested ||
		requested.protocol !== 'http:' ||
		!LOOPBACKS.has(requested.hostname)
	) {
		return false;
	}

	return client.redirectUris.some((registered) => {
		const allowed = URL.parse(registered);
		return (
			allowed !== null &&
			allowed.protocol === 'http:' &&
			allowed.hostname === requested.hostname &&
			allowed.pathname === requested.pathname &&
			allowed.search === requested.search
		);
	});
}

export function postLogoutRedirectUriAllowed(
	client: ClientSchemaType,
	value: string
): boolean {
	const parsed = URL.parse(value);
	if (!parsed) return false;
	return !!client.postLogoutRedirectUris.find(
		(allowed) => URL.parse(allowed)?.href === parsed.href
	);
}

export function includeSid(client: ClientSchemaType): boolean {
	return client.backchannelLogoutUri && client.backchannelLogoutSessionRequired;
}
