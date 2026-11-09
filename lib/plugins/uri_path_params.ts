import { Elysia } from 'elysia';

/**
 * The value of the path parameter `name`, decoded from the raw request path.
 *
 * Elysia 1.4.31 (GHSA-pxh4-839p-c8c8) keeps an encoded slash in a parameter as `%2F` while still
 * decoding `%25` to `%`, so `a/b` and a literal `a%2Fb` reach a handler as the same string. A
 * parameter that is a URI — a resource identifier, a client_id that is a URL — must come back exactly
 * as the caller encoded it, so it is decoded here from its own segment. The segment is counted from
 * the end of the route, so a prefix (`/:bucket`, a mounting path) never shifts it.
 */
function rawPathParam(
	request: Request,
	route: string,
	name: string
): string | undefined {
	const routeSegments = route.split('/');
	const at = routeSegments.indexOf(`:${name}`);
	if (at < 0) return undefined;

	const segments = new URL(request.url).pathname.split('/');
	if (segments.at(-1) === '' && routeSegments.at(-1) !== '') segments.pop();
	const raw = segments.at(at - routeSegments.length);
	if (raw === undefined) return undefined;

	try {
		return decodeURIComponent(raw);
	} catch {
		return undefined;
	}
}

/**
 * Elysia plugin: restore the named path parameters to their exact decoded values before validation,
 * for the routes of the instance that mounts it:
 *
 *   new Elysia().use(uriPathParams('clientId')).get('/reg/:clientId', ...)
 */
export function uriPathParams(...names: string[]) {
	return new Elysia().onTransform(
		{ as: 'scoped' },
		({ request, route, params }) => {
			const target = params as Record<string, string | undefined> | undefined;
			if (!target) return;
			for (const name of names) {
				if (target[name] === undefined) continue;
				const value = rawPathParam(request, route, name);
				if (value !== undefined) target[name] = value;
			}
		}
	);
}
