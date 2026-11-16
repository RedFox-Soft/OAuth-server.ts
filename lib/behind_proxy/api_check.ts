import { captureFault } from '../error_store/capture.js';
import { noteApiCheck, noteApiUse } from '../person_activity/record.js';
import { markActivityOf } from '../activity/note.js';
import { eventBus } from '../event_bus.js';
import { sameHost } from './address.js';
import { apiMetadataUrlOf } from './api_address.js';
import { addressedApi, type AddressedApi } from './api_find.js';
import { answer, type ApiReason } from './answers.js';
import { getProtectedResourceStore } from '../adapters/index.js';
import { conditionsInPlay, decideApiCall } from './api_decision.js';
import { personFacts } from './api_person.js';
import { factsForBelieved } from '../network_facts/lookup.js';
import { readBearer, type BearerRefusal } from './bearer.js';
import { believedAddress } from './believed_address.js';
import { noteAddress } from './usage.js';
import { hasControlCharacter } from './tools.js';
import { configuration } from '../configs/application.js';
import { signInOf } from '../resources/registry.js';
import {
	CHALLENGE_CODE_DESCRIPTION,
	CHALLENGE_RECENT_DESCRIPTION,
	hadCode
} from '../resources/sign_in_requirement.js';
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
	detail: {
		tool?: string | null;
		clientId?: string | null;
		accountId?: string | null;
	} = {}
): void {
	eventBus.emit('behind_proxy.api_decision', {
		bucketId: bucket._id,
		resource: api.identifier,
		outcome,
		reason,
		tool: detail.tool ?? null,
		clientId: detail.clientId ?? null,
		accountId: detail.accountId ?? null
	});
}

/*
 * A refusal or an ask for a new sign-in, on the activity of the person the token names (specs/133 FR-004): under the
 * API's own project, the only one a token of it can name a person of (lib/behind_proxy/api_person.ts), and never with
 * an address — the caller here is the agent's host, not the person.
 */
function noteForPerson(
	{ api }: AddressedApi,
	presented: { accountId: string | null; clientId: string },
	outcome: 'refused' | 'sign_in_again',
	reason: ApiReason,
	tool: string | null
): void {
	noteApiCheck({
		api,
		accountId: presented.accountId,
		clientId: presented.clientId,
		outcome,
		reason,
		tool
	});
}

/* RFC 6750 §3's characters for a quoted value: printable ASCII without `"` or `\`. */
function quotable(value: string): boolean {
	for (let i = 0; i < value.length; i++) {
		const c = value.charCodeAt(i);
		if (c < 0x20 || c > 0x7e || c === 0x22 || c === 0x5c) return false;
	}
	return true;
}

/* The `WWW-Authenticate` of a refusal about the token (RFC 6750 §3), always naming where the metadata is. */
export function challenge(
	metadataUrl: string,
	parameters: Record<string, string> = {}
): string {
	const pairs = Object.entries({
		...parameters,
		resource_metadata: metadataUrl
	})
		/*
		 * Only RFC 6750 §3's characters, so no value can close its quotes and add a parameter, and none outside Latin-1
		 * can make the header unbuildable, which would answer 500 (specs/130 research R7). A parameter with anything else
		 * is left out: every value here is a server constant, a declared scope or the metadata address.
		 */
		.filter(([, value]) => quotable(value))
		.map(([name, value]) => `${name}="${value}"`);
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
	request,
	route
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
			clientId: presented.clientId,
			accountId: presented.accountId
		});
		noteForPerson(addressed, presented, 'refused', 'unsafe_value', null);
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
	/*
	 * Everything after the token is one pure decision the console's "Check access" shares (specs/131 research R4): the
	 * API's own conditions, its sign-in requirement, the tools table and the named row's conditions. Here only what
	 * it is handed is looked up, and only when a condition in play needs it (research R6).
	 */
	const headers = {
		method: request.headers.get('mcp-method'),
		name: request.headers.get('mcp-name'),
		protocolVersion: request.headers.get('mcp-protocol-version')
	};
	const view = { signIn: signInOf(api), tools: api.tools };
	const inPlay = conditionsInPlay(view, headers);
	const network = factsForBelieved(believed.address, inPlay);
	const decided = decideApiCall(view, {
		token: {
			scopes: presented.scopes,
			signedInAt: presented.signedInAt,
			signedInWithCode: hadCode(presented.acr)
		},
		headers,
		person: await personFacts(api, presented.accountId, inPlay),
		address: believed.address,
		...(network ? { network } : {}),
		at: Date.now(),
		explain: false
	});
	switch (decided.outcome) {
		case 'allow': {
			emitDecision(addressed, 'allow', 'allowed', {
				tool: decided.tool,
				clientId: presented.clientId,
				accountId: presented.accountId
			});
			/* What the person used, and that they were active (specs/134): no read, no wait, never an address. */
			if (presented.accountId !== null) {
				noteApiUse({
					api,
					accountId: presented.accountId,
					clientId: presented.clientId,
					tool: decided.tool
				});
				markActivityOf(api.bucketId, presented.accountId, {
					route,
					method: request.method,
					clientId: presented.clientId
				});
			}
			return answer(200, 'allowed', identity);
		}
		case 'refuse': {
			emitDecision(addressed, 'refuse', decided.reason, {
				tool: decided.tool,
				clientId: presented.clientId,
				accountId: presented.accountId
			});
			noteForPerson(
				addressed,
				presented,
				'refused',
				decided.reason,
				decided.tool
			);
			return refused(decided.reason);
		}
		case 'insufficient': {
			emitDecision(addressed, 'refuse', 'insufficient_scope', {
				tool: decided.tool,
				clientId: presented.clientId,
				accountId: presented.accountId
			});
			noteForPerson(
				addressed,
				presented,
				'refused',
				'insufficient_scope',
				decided.tool
			);
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
		case 'sign_in': {
			/*
			 * How the person signed in (specs/130 research R6): a person's token whose sign-in does not meet the API's
			 * requirement is asked for a new one, in RFC 9470's words.
			 */
			const { unmet } = decided;
			const reason = unmet.code ? 'code_required' : 'sign_in_not_fresh';
			const maxAgeSeconds = view.signIn?.maxAgeSeconds;
			emitDecision(addressed, 'refuse', reason, {
				clientId: presented.clientId,
				accountId: presented.accountId
			});
			noteForPerson(addressed, presented, 'sign_in_again', reason, null);
			return answer(
				401,
				reason,
				{
					'WWW-Authenticate': challenge(metadataUrl, {
						error: 'insufficient_user_authentication',
						error_description: unmet.code
							? CHALLENGE_CODE_DESCRIPTION
							: CHALLENGE_RECENT_DESCRIPTION,
						...(unmet.code
							? { acr_values: configuration.acrMap.multi_factor }
							: {}),
						...(unmet.recent && maxAgeSeconds !== undefined
							? { max_age: String(maxAgeSeconds) }
							: {})
					})
				},
				reason
			);
		}
		case 'unknown':
			/* Only the console's explain mode answers this; the check never asks for it. */
			throw new Error('the check judged a request with an unknown input');
	}
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
