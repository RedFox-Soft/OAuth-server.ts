import { Elysia } from 'elysia';

import { getBucketStore } from '../adapters/index.js';
import { requestBucketFor } from '../admin/auth/bucketAddress.js';
import { ApplicationConfig } from '../configs/application.js';
import { issuerFor, type RequestBucket } from '../configs/issuer.js';
import { hostOfRequest } from '../consts/request_host.js';
import {
	isScimRoute,
	SCIM_BASE_PATH,
	SCIM_MAX_BODY_BYTES,
	SCIM_MEDIA_TYPE,
	SCIM_METADATA_BUCKET_ROUTE,
	SCIM_METADATA_ROUTE,
	SCIM_SCOPE
} from '../consts/scim.js';
import { captureFault } from '../error_store/capture.js';
import { OIDCProviderError, UnknownBucket } from '../helpers/errors.js';
import { originOf } from '../plugins/rateLimit.js';
import { scimBaseUrl } from '../provisioning/addresses.js';
import {
	resourceTypeById,
	resourceTypes,
	schemaById,
	schemas,
	serviceProviderConfig
} from './discovery.js';
import { ScimError, scimErrorBody } from './errors.js';
import { resolveScimPrincipal } from './principal.js';
import { chargeConnection, chargeUnauthenticated } from './rate_limit.js';
import {
	createUser,
	deleteUser,
	getUser,
	listUsers,
	patchUser,
	replaceUser,
	type ScimReply,
	type ScimRequestContext
} from './users.js';
import {
	createGroupResource,
	deleteGroupResource,
	getGroupResource,
	listGroups,
	patchGroup,
	replaceGroup
} from './groups.js';

/*
 * SCIM 2.0 at `<bucket issuer>/scim/v2` — mounted bare (the default bucket, and any bucket addressed by its
 * own host) and again beneath `/:bucket`, the way every other per-bucket endpoint is (lib/index.ts).
 *
 * Its own surface in every respect the protocol needs: its own error shape (the root handler stands aside
 * for every SCIM route), its own capture of faults it renders, its own body parser (Elysia leaves
 * `application/scim+json` unparsed), and its own per-connection rate limit in place of the per-origin one.
 */

const JSON_TYPES = new Set([SCIM_MEDIA_TYPE, 'application/json']);

function mediaTypeOf(header: string | null | undefined): string {
	return (header ?? '').split(';')[0].trim().toLowerCase();
}

function reply(result: ScimReply): Response {
	const headers: Record<string, string> = {
		...(result.status === 204
			? {}
			: { 'content-type': `${SCIM_MEDIA_TYPE}; charset=utf-8` }),
		...(result.headers ?? {})
	};
	return new Response(
		result.status === 204 ? null : JSON.stringify(result.body),
		{ status: result.status, headers }
	);
}

/*
 * The bucket the request addressed, the connection its credential belongs to, and the allowance it is
 * charged against — every SCIM handler's first act. A credential failure is charged per origin before it is
 * refused, so a token guesser is limited here as tightly as at the token endpoint.
 */
async function enter(
	request: Request,
	slug: string | undefined,
	server: unknown
): Promise<ScimRequestContext> {
	let addressed: RequestBucket;
	try {
		addressed = await requestBucketFor(slug, hostOfRequest(request));
	} catch (error) {
		if (error instanceof UnknownBucket) {
			throw new ScimError(
				404,
				undefined,
				'no SCIM endpoint is served at this address'
			);
		}
		throw error;
	}
	const bucket = await getBucketStore().find(addressed._id);
	const base = bucket ? scimBaseUrl(addressed) : null;
	if (!bucket || base === null) {
		throw new ScimError(
			404,
			undefined,
			'no SCIM endpoint is served at this address'
		);
	}

	let connection;
	try {
		connection = await resolveScimPrincipal(
			request.headers.get('authorization') ?? undefined,
			addressed
		);
	} catch (error) {
		if (error instanceof ScimError && error.status === 401) {
			chargeUnauthenticated(originOf(request, server));
		}
		throw error;
	}
	chargeConnection(connection._id);
	return {
		bucket,
		connection,
		base,
		leniency: { strict: ApplicationConfig['scim.strict'] === true }
	};
}

function assertJsonBody(request: Request): void {
	if (!JSON_TYPES.has(mediaTypeOf(request.headers.get('content-type')))) {
		throw new ScimError(
			415,
			undefined,
			'send the body as application/scim+json or application/json'
		);
	}
}

/* Everything raised beneath a SCIM route, in SCIM's shape. A fault is recorded, and its reference given. */
function asScimError(error: unknown, code: unknown): ScimError {
	if (error instanceof ScimError) return error;
	/* Elysia wraps whatever a parse hook throws in its own ParseError, so the parser's 413 rides as the cause. */
	if (
		code === 'PARSE' &&
		error instanceof Error &&
		error.cause instanceof ScimError
	) {
		return error.cause;
	}
	if (code === 'PARSE') {
		return new ScimError(
			400,
			'invalidSyntax',
			'the request body is not valid JSON'
		);
	}
	if (code === 'VALIDATION') {
		return new ScimError(400, 'invalidSyntax', 'the request is malformed');
	}
	if (code === 'NOT_FOUND') return new ScimError(404, undefined, 'not found');
	if (error instanceof OIDCProviderError && error.status === 404) {
		return new ScimError(404, undefined, 'not found');
	}
	return new ScimError(500, undefined, 'an internal error occurred');
}

type Handler = (context: ScimRequestContext) => Promise<ScimReply>;

export const scimApp = new Elysia({ name: 'scim' })
	/*
	 * Both JSON media types read here, so the size cap applies before anything is parsed and a body that is
	 * not JSON is a SCIM 400 rather than a framework error. Other types fall through to the framework and
	 * are refused with 415 by the handler that wanted a body.
	 */
	.onParse(async ({ request, contentType }) => {
		if (!JSON_TYPES.has(mediaTypeOf(contentType))) return;
		const declared = Number(request.headers.get('content-length') ?? '0');
		if (declared > SCIM_MAX_BODY_BYTES) {
			throw new ScimError(413, undefined, 'the request body is too large');
		}
		const text = await request.text();
		if (Buffer.byteLength(text, 'utf8') > SCIM_MAX_BODY_BYTES) {
			throw new ScimError(413, undefined, 'the request body is too large');
		}
		if (text.trim() === '') return null;
		try {
			return JSON.parse(text);
		} catch {
			throw new ScimError(
				400,
				'invalidSyntax',
				'the request body is not valid JSON'
			);
		}
	})
	/*
	 * The third place a fault is recorded (wiki/concepts/error-store-capture-sites.md): the root handler
	 * stands aside for SCIM routes, so a fault rendered here would otherwise never reach the store.
	 */
	.onError(({ error, code, route, request }) => {
		if (!isScimRoute(route)) return;
		const scim = asScimError(error, code);
		const reference =
			scim.status >= 500
				? captureFault({
						surface: 'scim',
						route,
						method: request.method,
						status: scim.status,
						errorCode: 'scim_error',
						error,
						headers: request.headers
					})
				: undefined;
		return reply({
			status: scim.status,
			body: scimErrorBody({
				status: scim.status,
				scimType: scim.scimType,
				detail: reference
					? `${scim.detail} (reference ${reference})`
					: scim.detail
			}),
			headers: { ...scim.headers }
		});
	})
	.get(
		`${SCIM_BASE_PATH}/ServiceProviderConfig`,
		async ({ request, params, server }) =>
			serve(request, params, server, async (c) => ({
				status: 200,
				body: serviceProviderConfig(c.base, c.leniency.strict)
			}))
	)
	.get(`${SCIM_BASE_PATH}/ResourceTypes`, async ({ request, params, server }) =>
		serve(request, params, server, async (c) => ({
			status: 200,
			body: resourceTypes(c.base)
		}))
	)
	.get(
		`${SCIM_BASE_PATH}/ResourceTypes/:resourceTypeId`,
		async ({ request, params, server }) =>
			serve(request, params, server, async (c) => ({
				status: 200,
				body: resourceTypeById(c.base, params.resourceTypeId)
			}))
	)
	.get(`${SCIM_BASE_PATH}/Schemas`, async ({ request, params, server }) =>
		serve(request, params, server, async (c) => ({
			status: 200,
			body: schemas(c.base)
		}))
	)
	.get(
		`${SCIM_BASE_PATH}/Schemas/:schemaId`,
		async ({ request, params, server }) =>
			serve(request, params, server, async (c) => ({
				status: 200,
				body: schemaById(c.base, params.schemaId)
			}))
	)
	.get(`${SCIM_BASE_PATH}/Users`, async ({ request, params, server }) =>
		serve(request, params, server, (c) =>
			listUsers(c, new URL(request.url).searchParams)
		)
	)
	.post(`${SCIM_BASE_PATH}/Users`, async ({ request, params, server, body }) =>
		serve(request, params, server, (c) => {
			assertJsonBody(request);
			return createUser(c, body);
		})
	)
	.get(`${SCIM_BASE_PATH}/Users/:userId`, async ({ request, params, server }) =>
		serve(request, params, server, (c) => getUser(c, params.userId))
	)
	.put(
		`${SCIM_BASE_PATH}/Users/:userId`,
		async ({ request, params, server, body }) =>
			serve(request, params, server, (c) => {
				assertJsonBody(request);
				return replaceUser(c, params.userId, body);
			})
	)
	.patch(
		`${SCIM_BASE_PATH}/Users/:userId`,
		async ({ request, params, server, body }) =>
			serve(request, params, server, (c) => {
				assertJsonBody(request);
				return patchUser(c, params.userId, body);
			})
	)
	.delete(
		`${SCIM_BASE_PATH}/Users/:userId`,
		async ({ request, params, server }) =>
			serve(request, params, server, (c) => deleteUser(c, params.userId))
	)
	.get(`${SCIM_BASE_PATH}/Groups`, async ({ request, params, server }) =>
		serve(request, params, server, (c) =>
			listGroups(c, new URL(request.url).searchParams)
		)
	)
	.post(`${SCIM_BASE_PATH}/Groups`, async ({ request, params, server, body }) =>
		serve(request, params, server, (c) => {
			assertJsonBody(request);
			return createGroupResource(c, body);
		})
	)
	.get(
		`${SCIM_BASE_PATH}/Groups/:groupId`,
		async ({ request, params, server }) =>
			serve(request, params, server, (c) =>
				getGroupResource(c, params.groupId, new URL(request.url).searchParams)
			)
	)
	.put(
		`${SCIM_BASE_PATH}/Groups/:groupId`,
		async ({ request, params, server, body }) =>
			serve(request, params, server, (c) => {
				assertJsonBody(request);
				return replaceGroup(c, params.groupId, body);
			})
	)
	.patch(
		`${SCIM_BASE_PATH}/Groups/:groupId`,
		async ({ request, params, server, body }) =>
			serve(request, params, server, (c) => {
				assertJsonBody(request);
				return patchGroup(c, params.groupId, body);
			})
	)
	.delete(
		`${SCIM_BASE_PATH}/Groups/:groupId`,
		async ({ request, params, server }) =>
			serve(request, params, server, (c) =>
				deleteGroupResource(c, params.groupId)
			)
	);

async function serve(
	request: Request,
	/* Absent on a bare route with no path parameter: Elysia passes none rather than an empty object. */
	params: Record<string, string | undefined> | undefined,
	server: unknown,
	handler: Handler
): Promise<Response> {
	const context = await enter(request, params?.bucket, server);
	return reply(await handler(context));
}

/*
 * RFC 9728 metadata for a bucket's SCIM resource — unauthenticated, as metadata is, and gated with the
 * endpoint it describes. Mounted once: the bare route answers the default bucket and host-addressed ones,
 * the inserted one (`…/:bucket/scim/v2`, §3.1) answers path-addressed ones.
 */
async function metadataFor(
	request: Request,
	slug: string | undefined
): Promise<Record<string, unknown>> {
	const addressed = await requestBucketFor(slug, hostOfRequest(request));
	const resource = scimBaseUrl(addressed);
	if (resource === null) throw new UnknownBucket();
	return {
		resource,
		authorization_servers: [issuerFor(addressed)],
		scopes_supported: [SCIM_SCOPE],
		bearer_methods_supported: ['header'],
		resource_name: 'SCIM provisioning'
	};
}

export const scimMetadataApp = new Elysia({ name: 'scim-metadata' })
	.get(SCIM_METADATA_ROUTE, ({ request }) => metadataFor(request, undefined))
	.get(SCIM_METADATA_BUCKET_ROUTE, ({ request, params }) =>
		metadataFor(request, params.bucket)
	);
