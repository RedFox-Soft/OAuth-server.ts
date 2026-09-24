/*
 * Rich Authorization Request transforms. These implement the generic reading of RFC 9396 §7 ("The AS
 * MUST also return the authorization_details as granted by the resource owner and assigned to the
 * respective access token") and §9 (for a resource server, the details "filtered to the specific
 * audience"). Neither is domain-specific, so neither needs a deployment to supply it — a hook that
 * throws is not a default. The override registry still wins for deployments that need their own
 * shaping.
 */

// Structural, and only as wide as these four functions actually read. Authorization details are
// arbitrary client JSON, so they stay `unknown` and are narrowed where they are inspected.
interface RarResourceServer {
	identifier(): string;
}

interface RarContext {
	// Any endpoint's parameters; the RAR seams read only authorization_details.
	params: Record<string, unknown> & { authorization_details?: unknown };
	entities: {
		Grant?: { getRarFiltered(requested: unknown): unknown[] };
		AuthorizationCode?: { payload: { rar?: unknown } };
		RefreshToken?: { payload: { rar?: unknown } };
	};
}

/*
 * A detail carrying no `locations` is KEPT rather than dropped: `locations` is optional in §2, so its
 * absence means the detail is not location-scoped, not that it applies nowhere.
 */
function filterToResourceServer(
	rar: unknown,
	resourceServer: RarResourceServer | undefined
) {
	if (!Array.isArray(rar)) {
		return [];
	}

	const identifier = resourceServer?.identifier();
	return rar.filter((detail) => {
		const locations = (detail as { locations?: unknown })?.locations;
		if (!Array.isArray(locations)) {
			return true;
		}
		return locations.includes(identifier);
	});
}

export function rarForAuthorizationCode(oidc: RarContext) {
	// The requested details intersected with what the resource owner granted. Grant#getRarFiltered
	// owns the trusted-grant case, so an override of this function cannot lose it.
	return oidc.entities.Grant?.getRarFiltered(oidc.params.authorization_details);
}

export function rarForCodeResponse(
	oidc: RarContext,
	resourceServer: RarResourceServer
) {
	return filterToResourceServer(
		oidc.entities.AuthorizationCode?.payload.rar,
		resourceServer
	);
}

export function rarForRefreshTokenResponse(
	oidc: RarContext,
	resourceServer: RarResourceServer
) {
	return filterToResourceServer(
		oidc.entities.RefreshToken?.payload.rar,
		resourceServer
	);
}

export function rarForIntrospectionResponse(
	_oidc: RarContext,
	// Any introspectable token; a client-credentials token carries no details at all.
	token: { payload: Record<string, unknown> & { rar?: unknown } }
) {
	// The resource server is the intended audience of an introspection response, so its details are
	// returned unchanged.
	return token.payload.rar;
}
