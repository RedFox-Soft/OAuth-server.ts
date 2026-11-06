import { captureFault } from '../error_store/capture.js';
import { eventBus } from '../event_bus.js';
import { sameHost } from './address.js';
import { apiMetadataUrlOf } from './api_address.js';
import { addressedApi, type AddressedApi } from './api_find.js';
import { answer, type ApiReason } from './answers.js';
import { getProtectedResourceStore } from '../adapters/index.js';
import { accessRefusal } from './api_person.js';
import { readBearer, type BearerRefusal } from './bearer.js';
import { believedAddress } from './believed_address.js';
import { noteAddress } from './usage.js';
import { decideTool, decodeMcpName, hasControlCharacter } from './tools.js';
import {
	chargeApp,
	chargeUnknown,
	checkCallerOf,
	CheckRateLimited
} from './rate_limit.js';

/*
 * The check a reverse proxy makes before passing a request to an API whose tokens it checks (specs/123,
 * contracts/api-check.md). Every answer carries `X-Auth-Reason` and `Cache-Control: no-store`, and a fault is
 * answered `500`, never `2xx`: a proxy passes the request on for any success.
 */

export interface ApiCheckRequest {
	params: unknown;
	request: Request;
	route: string;
}

const FORWARDED_HOST = 'x-forwarded-host';
const FORWARDED_METHOD = 'x-forwarded-method';

/* Sent empty when no token is named, so an API never reads a value a client put there. */
const IDENTITY_HEADERS = [
	'X-Auth-Subject',
	'X-Auth-Client',
	'X-Auth-Scope'
] as const;

/*
 * The one refusal for an unknown project, a project scheduled for deletion, the administrators' project, an
 * unknown API, an API its own server checks, another project's API and a host that is not the API's. Built by one
 * function, so nothing about the answer can tell a caller which it was.
 */
function notFound(): Response {
	return answer(403, 'not_found', {}, 'not_found');
}

function refused(reason: ApiReason): Response {
	return answer(403, reason, {}, reason);
}

function emitDecision(
	{ bucket, api }: AddressedApi,
	outcome: 'allow' | 'refuse',
	reason: ApiReason,
	detail: { tool?: string | null; clientId?: string | null } = {}
): void {
	eventBus.emit('behind_proxy.api_decision', {
		bucketId: bucket._id,
		resource: api.identifier,
		outcome,
		reason,
		tool: detail.tool ?? null,
		clientId: detail.clientId ?? null
	});
}

/* The `WWW-Authenticate` of a refusal about the token (RFC 6750 §3), always naming where the metadata is. */
function challenge(
	metadataUrl: string,
	parameters: Record<string, string> = {}
): string {
	const pairs = Object.entries({
		...parameters,
		resource_metadata: metadataUrl
	}).map(([name, value]) => `${name}="${value}"`);
	return `Bearer ${pairs.join(', ')}`;
}

/* What each refusal about the token says beside where the metadata is (contracts/api-check.md). */
const TOKEN_CHALLENGE: Record<BearerRefusal, Record<string, string>> = {
	missing_token: {},
	invalid_token: { error: 'invalid_token' },
	bound_token_unsupported: {
		error: 'invalid_token',
		error_description:
			'sender-constrained tokens are not accepted at this proxy'
	}
};

async function evaluate({
	params,
	request
}: ApiCheckRequest): Promise<Response> {
	const addressed = await addressedApi(params, request);
	if (!addressed) {
		chargeUnknown(request);
		return notFound();
	}
	chargeApp(`api:${addressed.checkId}`);
	const { bucket, api } = addressed;

	const forwardedHost = request.headers.get(FORWARDED_HOST);
	const forwardedMethod = request.headers.get(FORWARDED_METHOD);
	if (!forwardedHost || !forwardedMethod) {
		return refused('missing_forwarded');
	}
	/*
	 * As for an app (lib/behind_proxy/check.ts): the forwarded host is only compared, never used to choose, so it
	 * can fail this check and do nothing else.
	 */
	if (!sameHost(forwardedHost, new URL(api.identifier).origin)) {
		return notFound();
	}

	/*
	 * A browser never attaches a credential to a CORS preflight, and a preflight invokes nothing, so it passes
	 * before any token is read (research R9) — every identity header present and empty, so none a client sent
	 * survives.
	 */
	if (
		forwardedMethod.toUpperCase() === 'OPTIONS' &&
		request.headers.has('access-control-request-method')
	) {
		emitDecision(addressed, 'allow', 'preflight');
		return answer(
			200,
			'preflight',
			Object.fromEntries(IDENTITY_HEADERS.map((name) => [name, '']))
		);
	}

	const metadataUrl = apiMetadataUrlOf(bucket, api.identifier);
	const presented = await readBearer(api, request);
	if (!presented.ok) {
		emitDecision(addressed, 'refuse', presented.reason);
		return answer(
			401,
			presented.reason,
			{
				'WWW-Authenticate': challenge(
					metadataUrl,
					TOKEN_CHALLENGE[presented.reason]
				)
			},
			presented.reason
		);
	}

	const identity = {
		'X-Auth-Subject': presented.subject,
		'X-Auth-Client': presented.clientId,
		'X-Auth-Scope': presented.scope
	};
	/* Refused rather than sent as a header the proxy would split; no token this server signs carries one. */
	if (Object.values(identity).some(hasControlCharacter)) {
		emitDecision(addressed, 'refuse', 'unsafe_value', {
			clientId: presented.clientId
		});
		return refused('unsafe_value');
	}
	/*
	 * Who may call the API at all (specs/124 contracts/check.md), before the tools table: the person behind the
	 * token, then where and when. The address is believed only from a proxy that shows the project's key, and is
	 * only compared.
	 */
	const believed = await believedAddress(request, bucket._id);
	noteAddress(
		{
			key: `api:${addressed.checkId}`,
			write: (seen) =>
				getProtectedResourceStore().noteProxyAddress(
					api.namespace,
					api.identifier,
					{
						...(seen.provenAt ? { proxyAddressProvenAt: seen.provenAt } : {}),
						...(seen.forgedAt ? { proxyAddressForgedAt: seen.forgedAt } : {})
					}
				)
		},
		believed.flags
	);
	const accessRefused = await accessRefusal(
		api,
		presented.accountId,
		believed.address
	);
	if (accessRefused) {
		emitDecision(addressed, 'refuse', accessRefused, {
			clientId: presented.clientId
		});
		return refused(accessRefused);
	}
	/*
	 * The tools table (research R6). The headers mirror a body the proxy never sees, so they decide only for a
	 * client whose server must have checked them against it; `decideTool` sends every other client to the
	 * administrator's choice for old clients.
	 */
	const mcpName = request.headers.get('mcp-name');
	const decided = decideTool({
		table: api.tools,
		method: request.headers.get('mcp-method'),
		name: mcpName,
		protocolVersion: request.headers.get('mcp-protocol-version'),
		scopes: presented.scopes
	});
	const decoded = mcpName === null ? null : decodeMcpName(mcpName);
	const detail = {
		tool: decoded && !decoded.bad ? decoded.name : null,
		clientId: presented.clientId
	};
	if (decided.outcome === 'insufficient') {
		emitDecision(addressed, 'refuse', 'insufficient_scope', detail);
		return answer(
			403,
			'insufficient_scope',
			{
				'WWW-Authenticate': challenge(metadataUrl, {
					error: 'insufficient_scope',
					scope: decided.needed.join(' ')
				})
			},
			'insufficient_scope'
		);
	}
	if (decided.outcome === 'refuse') {
		emitDecision(addressed, 'refuse', decided.reason, detail);
		return refused(decided.reason);
	}

	emitDecision(addressed, 'allow', 'allowed', detail);
	return answer(200, 'allowed', identity);
}

export async function answerApiCheck(
	input: ApiCheckRequest
): Promise<Response> {
	try {
		return await evaluate(input);
	} catch (error) {
		const { request } = input;
		if (error instanceof CheckRateLimited) {
			return answer(
				429,
				'rate_limited',
				{ 'Retry-After': String(error.retryAfterSeconds) },
				'rate_limited'
			);
		}
		const reference = captureFault({
			surface: 'oauth',
			route: input.route,
			method: request.method,
			status: 500,
			errorCode: 'behind_proxy_fault',
			error,
			callerAddress: checkCallerOf(request),
			headers: request.headers
		});
		return answer(
			500,
			'server_error',
			{},
			reference ? `server_error (reference ${reference})` : 'server_error'
		);
	}
}
