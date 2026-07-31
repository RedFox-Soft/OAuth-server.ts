import { Elysia } from 'elysia';
import { publicJWKS } from 'lib/configs/keystore.js';
import { routeNames } from 'lib/consts/param_list.js';
import { corsOpen } from 'lib/plugins/cors.js';

// corsOpen must precede the route: an Elysia hook only affects routes declared after it, so moving
// this below the .get() silently stops emitting the header a browser needs to read the key set.
export const jwks = new Elysia()
	.use(corsOpen)
	.get(routeNames.jwks, function () {
		// Read per request, not captured: publicJWKS is mutated in place when a key is hot-applied
		// or the key set is reloaded.
		const { keys } = publicJWKS;
		return new Response(JSON.stringify({ keys }), {
			headers: {
				'Content-Type': 'application/jwk-set+json; charset=utf-8'
			}
		});
	});
