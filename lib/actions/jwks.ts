import { Elysia } from 'elysia';
import { publicJWKS } from 'lib/configs/keystore.js';
import { routeNames } from 'lib/consts/param_list.js';

export const jwks = new Elysia().get(routeNames.jwks, function () {
	// Read per request, not captured: publicJWKS is mutated in place when a key is hot-applied
	// or the key set is reloaded.
	const { keys } = publicJWKS;
	return new Response(JSON.stringify({ keys }), {
		headers: {
			'Content-Type': 'application/jwk-set+json; charset=utf-8'
		}
	});
});
