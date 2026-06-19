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

export function redirectUriAllowed(
	client: ClientSchemaType,
	value: string
): boolean {
	return client.redirectUris.includes(value);
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
