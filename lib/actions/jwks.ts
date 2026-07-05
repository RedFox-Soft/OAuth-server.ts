import { Elysia } from 'elysia';
import instance from '../helpers/weak_cache.ts';
import { provider } from 'lib/provider.js';
import { routeNames } from 'lib/consts/param_list.js';

export const jwks = new Elysia().get(routeNames.jwks, function () {
	const { keys } = instance(provider).jwks;
	return new Response(JSON.stringify({ keys }), {
		headers: {
			'Content-Type': 'application/jwk-set+json; charset=utf-8'
		}
	});
});
