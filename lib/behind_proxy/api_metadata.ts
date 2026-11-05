import { addressedApi } from './api_find.js';
import { apiIssuerOf } from './bearer.js';

/*
 * The protected-resource metadata (RFC 9728) of an API whose tokens the proxy checks, served by the project so the
 * server behind the proxy serves nothing (specs/123 R5). A client follows `resource_metadata` from the check's
 * `401` to here, and checks that `resource` is the URL it called, which it is: the API's identifier.
 *
 * Every other request gets one empty `404`, the same whether the project, the id or the mode was wrong.
 */
export async function answerApiMetadata({
	params,
	request
}: {
	params: unknown;
	request: Request;
}): Promise<Response> {
	const addressed = await addressedApi(params, request);
	if (!addressed) {
		return new Response(null, {
			status: 404,
			headers: { 'Cache-Control': 'no-store' }
		});
	}
	const { api } = addressed;
	const { issuer } = await apiIssuerOf(api);
	return new Response(
		JSON.stringify({
			resource: api.identifier,
			authorization_servers: [issuer],
			scopes_supported: api.scopes,
			bearer_methods_supported: ['header'],
			resource_name: api.name
		}),
		{
			status: 200,
			headers: {
				'Content-Type': 'application/json',
				/* A public document a browser-based MCP client must be able to read from its own origin. */
				'Access-Control-Allow-Origin': '*',
				'Cache-Control': 'public, max-age=60'
			}
		}
	);
}
