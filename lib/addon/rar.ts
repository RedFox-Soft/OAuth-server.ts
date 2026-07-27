import { mustChange } from './_warn.ts';

// Rich Authorization Request transforms. These have no meaningful default: a
// deployment enabling RAR must define how requested/granted authorization_details
// are shaped for the code, token responses, and introspection. The defaults warn
// via mustChange and refuse to run so a missing implementation fails loudly.

export function rarForAuthorizationCode(_ctx) {
	// decision points:
	// - ctx.oidc.client
	// - ctx.oidc.resourceServers
	// - ctx.oidc.params.authorization_details (unparsed authorization_details from the authorization request)
	// - ctx.oidc.grant.rar (authorization_details granted)
	mustChange(
		'features.richAuthorizationRequests.rarForAuthorizationCode',
		'transform the requested and granted RAR details to be passed in the authorization code'
	);
	throw new Error(
		'features.richAuthorizationRequests.rarForAuthorizationCode not implemented'
	);
}

export function rarForCodeResponse(_ctx, _resourceServer) {
	mustChange(
		'features.richAuthorizationRequests.rarForCodeResponse',
		'transform the requested and granted RAR details to be returned in the Access Token Response as authorization_details as well as assigned to the issued Access Token'
	);
	throw new Error(
		'features.richAuthorizationRequests.rarForCodeResponse not implemented'
	);
}

export function rarForRefreshTokenResponse(_ctx, _resourceServer) {
	mustChange(
		'features.richAuthorizationRequests.rarForRefreshTokenResponse',
		'transform the requested and granted RAR details to be returned in the Access Token Response as authorization_details as well as assigned to the issued Access Token'
	);
	throw new Error(
		'features.richAuthorizationRequests.rarForRefreshTokenResponse not implemented'
	);
}

export function rarForIntrospectionResponse(_ctx, _token) {
	mustChange(
		'features.richAuthorizationRequests.rarForIntrospectionResponse',
		"transform the token's stored RAR details to be returned in the Introspection Response"
	);
	throw new Error(
		'features.richAuthorizationRequests.rarForIntrospectionResponse not implemented'
	);
}
