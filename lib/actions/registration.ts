import { Elysia, t } from 'elysia';

import omitBy from '../helpers/_/omit_by.ts';
import constantEquals from '../helpers/constant_equals.ts';
import epochTime from '../helpers/epoch_time.ts';
import { InvalidToken, InvalidRequest } from '../helpers/errors.ts';
import instance from '../helpers/weak_cache.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import addClient from '../helpers/add_client.ts';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { provider } from 'lib/provider.js';
import { routeNames } from 'lib/consts/param_list.js';
import { ISSUER } from 'lib/configs/env.js';
import {
	RegistrationResponse,
	OAuthError
} from 'lib/shared/response_schemas.js';

const FORBIDDEN = [
	'registration_access_token',
	'registration_client_uri',
	'client_secret_expires_at',
	'client_id_issued_at'
];

// RFC 7591/7592 use snake_case on the wire, but the Client model keeps the base
// registration attributes (client_id/client_secret/redirect_uris/… and the two
// request-object signing options) as camelCase/dotted canonical keys internally —
// they are NOT in RECOGNIZED_METADATA, so the schema engine neither reads them from
// snake input nor snakes them back in metadata(). Translate at this boundary only —
// snake→canonical on the incoming body, canonical→snake on the metadata() response —
// so the registration contract stays standards-compliant while the rest of the server
// uses the single canonical name. (Recognized metadata such as client_secret_expires_at
// and token_endpoint_auth_method already round-trips through the schema, so it is absent
// from this map.)
const REQUEST_OBJECT_ALG_WIRE_MAP = {
	client_id: 'clientId',
	client_secret: 'clientSecret',
	redirect_uris: 'redirectUris',
	application_type: 'applicationType',
	response_types: 'responseTypes',
	response_modes: 'responseModes',
	grant_types: 'grantTypes',
	subject_type: 'subjectType',
	request_object_signing_alg: 'requestObject.signingAlg',
	backchannel_authentication_request_signing_alg:
		'requestObject.backChannelSigningAlg'
};

type Body = Record<string, unknown>;

function snakeToCanonical(body: Body) {
	for (const [snake, dotted] of Object.entries(REQUEST_OBJECT_ALG_WIRE_MAP)) {
		if (snake in body) {
			body[dotted] = body[snake];
			delete body[snake];
		}
	}
	return body;
}

function canonicalToSnake(metadata: Body) {
	for (const [snake, dotted] of Object.entries(REQUEST_OBJECT_ALG_WIRE_MAP)) {
		if (dotted in metadata) {
			metadata[snake] = metadata[dotted];
			delete metadata[dotted];
		}
	}
	return metadata;
}

// The registration routes authenticate with an opaque bearer token, not client auth. The token is
// taken from the Authorization header (never the JSON body — a token in the body reads as absent),
// and additionally from the `access_token` query on read. Absence is `invalid_request` (400) with
// the RFC challenge text; an unresolved token surfaces later as `invalid_token` (401).
function readBearer(
	authorization: string | undefined,
	query: Record<string, unknown> | undefined,
	allowQuery: boolean
) {
	if (typeof authorization === 'string') {
		const [scheme, value] = authorization.split(' ');
		if (scheme?.toLowerCase() === 'bearer' && value) {
			return value;
		}
	}
	if (
		allowQuery &&
		typeof query?.access_token === 'string' &&
		query.access_token
	) {
		return query.access_token;
	}
	throw new InvalidRequest('no access token provided');
}

// `failWith` in the suite asserts every registration auth failure carries `WWW-Authenticate: Bearer
// realm="<issuer>"`. The global error handler enriches 401s with error/error_description from the
// bearer header; the realm-only baseline set here is what remains on the 400 "no access token
// provided" case (which has no Authorization header for the global handler to key off).
function setBearerRealm(set: { headers: Record<string, string> }) {
	set.headers['WWW-Authenticate'] = `Bearer realm="${ISSUER}"`;
}

async function authenticate(
	oidc: OIDCContext<Body>,
	clientId: string,
	token: string
) {
	const regAccessToken = await provider.RegistrationAccessToken.find(token);
	if (!regAccessToken) {
		throw new InvalidToken('token not found');
	}

	const client = await provider.Client.find(clientId);

	// Token fields live under `.payload.*` (top-level accessors were removed with the
	// IN_PAYLOAD refactor); `client.*` stays direct because the validated client is a plain
	// object, not a payload-wrapped model.
	if (client?.clientId !== regAccessToken.payload.clientId) {
		await regAccessToken.destroy();
		throw new InvalidToken('client mismatch');
	}

	oidc.entity('Client', client);
	oidc.entity('RegistrationAccessToken', regAccessToken);

	return { client, regAccessToken };
}

async function validateInitialAccessToken(
	oidc: OIDCContext<Body>,
	token: string | undefined
) {
	const initialAccessToken =
		ApplicationConfig['registration.initialAccessToken'];
	switch (initialAccessToken && typeof initialAccessToken) {
		case 'boolean': {
			const iat = await provider.InitialAccessToken.find(
				readBearer(token, undefined, false)
			);
			if (!iat) {
				throw new InvalidToken('initial access token not found');
			}
			oidc.entity('InitialAccessToken', iat);
			break;
		}
		case 'string': {
			// The switch guarantees a string here; the config value's declared type is a
			// union (false | string | true), which TypeScript does not narrow off `typeof`.
			const valid = constantEquals(
				initialAccessToken as string,
				readBearer(token, undefined, false),
				1000
			);
			if (!valid) {
				throw new InvalidToken('invalid initial access token value');
			}
			break;
		}
		default:
	}
}

async function create({ body, headers, request, set }) {
	const contentType = request.headers.get('content-type') || '';
	if (!contentType.includes('application/json')) {
		throw new InvalidRequest(
			'only application/json content-type bodies are supported on POST /reg'
		);
	}

	const requestBody: Body = (body as Body) ?? {};
	const oidc = new OIDCContext<Body>(requestBody, headers, 'registration');

	await validateInitialAccessToken(oidc, headers.authorization);

	const { idFactory, secretFactory } = instance(provider).features.registration;
	const issueRegistrationAccessToken =
		ApplicationConfig['registration.issueRegistrationAccessToken'];
	const properties: Body = {};
	const clientId = idFactory({ oidc });

	let rat;

	if (
		issueRegistrationAccessToken === true ||
		(typeof issueRegistrationAccessToken === 'function' &&
			issueRegistrationAccessToken({ oidc }))
	) {
		rat = new provider.RegistrationAccessToken({ clientId });
		oidc.entity('RegistrationAccessToken', rat);
	}

	Object.assign(properties, requestBody, {
		client_id: clientId,
		client_id_issued_at: epochTime()
	});
	snakeToCanonical(properties);

	const { Client } = provider;
	const secretRequired = Client.needsSecret(properties);

	if (secretRequired) {
		Object.assign(properties, {
			clientSecret: await secretFactory({ oidc }),
			client_secret_expires_at: 0
		});
	} else {
		delete properties.clientSecret;
		delete properties.client_secret_expires_at;
	}

	const iatPolicies = oidc.entities.InitialAccessToken?.payload?.policies;
	if (iatPolicies) {
		const implementations = ApplicationConfig['registration.policies'];
		for (const policy of iatPolicies) {
			await implementations[policy]({ oidc }, properties);
		}

		if (rat && !('policies' in rat.payload)) {
			rat.payload.policies = iatPolicies;
		}
	}

	const client = await addClient(provider, properties, { store: true });
	oidc.entity('Client', client);

	const responseBody: Body = canonicalToSnake(client.metadata());

	if (rat) {
		Object.assign(responseBody, {
			registration_client_uri: oidc.urlFor('client', { clientId }),
			registration_access_token: await rat.save()
		});
	}

	set.status = 201;
	provider.emit('registration_create.success', { oidc }, client);

	return responseBody;
}

async function read({ params, headers, query, set }) {
	setBearerRealm(set);
	const oidc = new OIDCContext<Body>({}, headers, 'registration');
	const token = readBearer(headers.authorization, query, true);
	const { client } = await authenticate(oidc, params.clientId, token);

	if (client.noManage) {
		throw new InvalidRequest(
			'client does not have permission to read its record',
			403
		);
	}

	const responseBody: Body = canonicalToSnake(client.metadata());

	Object.assign(responseBody, {
		registration_access_token: token,
		registration_client_uri: oidc.urlFor('client', {
			clientId: params.clientId
		})
	});

	return responseBody;
}

async function update({ params, body, headers, set }) {
	setBearerRealm(set);
	const requestBody: Body = (body as Body) ?? {};
	const oidc = new OIDCContext<Body>(requestBody, headers, 'registration');
	const token = readBearer(headers.authorization, undefined, false);
	const { client, regAccessToken } = await authenticate(
		oidc,
		params.clientId,
		token
	);

	const hit = FORBIDDEN.find((field) => requestBody[field] !== undefined);
	if (hit) {
		throw new InvalidRequest(`request MUST NOT include the ${hit} field`);
	}

	if (requestBody.client_id !== client.clientId) {
		throw new InvalidRequest(
			"provided client_id does not match the authenticated client's one"
		);
	}

	if ('client_secret' in requestBody) {
		const clientSecretValid = constantEquals(
			typeof requestBody.client_secret === 'string'
				? requestBody.client_secret
				: '',
			client.clientSecret || '',
			1000
		);

		if (!clientSecretValid) {
			throw new InvalidRequest(
				"provided client_secret does not match the authenticated client's one"
			);
		}
	}

	if (client.noManage) {
		throw new InvalidRequest(
			'client does not have permission to update its record',
			403
		);
	}

	const properties = snakeToCanonical(
		omitBy(
			{
				client_id: client.clientId,
				client_id_issued_at: client.clientIdIssuedAt,
				...requestBody
			},
			(value) => value === null || value === ''
		)
	);

	const { secretFactory } = instance(provider).features.registration;

	const secretRequired =
		!client.clientSecret && provider.Client.needsSecret(properties);

	if (secretRequired) {
		Object.assign(properties, {
			clientSecret: await secretFactory({ oidc }),
			client_secret_expires_at: 0
		});
	} else {
		Object.assign(properties, {
			clientSecret: client.clientSecret,
			client_secret_expires_at: client.clientSecretExpiresAt
		});
	}

	if (regAccessToken.payload.policies) {
		const { policies } = regAccessToken.payload;
		const implementations = ApplicationConfig['registration.policies'];
		for (const policy of policies) {
			await implementations[policy]({ oidc }, properties);
		}
	}

	const nextClient = await addClient(provider, properties, { store: true });

	const responseBody: Body = canonicalToSnake(nextClient.metadata());

	Object.assign(responseBody, {
		registration_access_token: token,
		registration_client_uri: oidc.urlFor('client', {
			clientId: params.clientId
		})
	});

	const rotateRegistrationAccessToken =
		ApplicationConfig['registrationManagement.rotateRegistrationAccessToken'];
	if (
		rotateRegistrationAccessToken === true ||
		(typeof rotateRegistrationAccessToken === 'function' &&
			(await rotateRegistrationAccessToken({ oidc })))
	) {
		oidc.entity('RotatedRegistrationAccessToken', regAccessToken);
		const rat = new provider.RegistrationAccessToken({
			client,
			policies: regAccessToken.payload.policies
		});

		await regAccessToken.destroy();

		oidc.entity('RegistrationAccessToken', rat);
		responseBody.registration_access_token = await rat.save();
	}

	provider.emit('registration_update.success', { oidc }, nextClient);

	return responseBody;
}

async function remove({ params, headers, set }) {
	setBearerRealm(set);
	const oidc = new OIDCContext<Body>({}, headers, 'registration');
	const token = readBearer(headers.authorization, undefined, false);
	const { client, regAccessToken } = await authenticate(
		oidc,
		params.clientId,
		token
	);

	if (client.noManage) {
		throw new InvalidRequest(
			'client does not have permission to delete its record',
			403
		);
	}

	await provider.Client.adapter.destroy(client.clientId);
	await regAccessToken.destroy();

	set.status = 204;
	provider.emit('registration_delete.success', { oidc }, client);
}

const OptionalBody = t.Optional(t.Record(t.String(), t.Unknown()));
const responses = {
	200: RegistrationResponse,
	201: RegistrationResponse,
	204: RegistrationResponse,
	400: OAuthError,
	401: OAuthError,
	403: OAuthError
};

export const registration = new Elysia()
	.post(routeNames.registration, create, {
		body: OptionalBody,
		response: responses
	})
	.get(`${routeNames.registration}/:clientId`, read, {
		response: responses
	})
	.put(`${routeNames.registration}/:clientId`, update, {
		body: OptionalBody,
		response: responses
	})
	.delete(`${routeNames.registration}/:clientId`, remove, {
		response: responses
	});
