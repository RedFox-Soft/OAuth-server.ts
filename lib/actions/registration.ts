import { Elysia, t } from 'elysia';

import omitBy from '../helpers/_/omit_by.ts';
import constantEquals from '../helpers/constant_equals.ts';
import epochTime from '../helpers/epoch_time.ts';
import { InvalidToken, InvalidRequest } from '../helpers/errors.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import addClient from '../helpers/add_client.ts';
import { idFactory, secretFactory } from '../addon/index.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { Client } from 'lib/models/client.js';
import { reclaimUnusedRegistrations } from 'lib/models/client/dynamic_registration.js';
import { snakeToCanonical, canonicalToSnake } from 'lib/models/client/wire.js';
import { InitialAccessToken } from 'lib/models/initial_access_token.js';
import { RegistrationAccessToken } from 'lib/models/registration_access_token.js';
import { eventBus } from 'lib/event_bus.js';
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

/*
 * snake_case on the wire, canonical names inside — translated at this boundary only, so the
 * registration contract stays standards-compliant while the rest of the server uses one name per
 * field. The map itself moved to `lib/models/client/wire.ts` when client description documents came
 * to need the same translation; two copies of it would drift, and a drifted entry silently ignores a
 * metadata field.
 */
type Body = Record<string, unknown>;

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
	const regAccessToken = await RegistrationAccessToken.find(token, {
		error: new InvalidToken('token not found')
	});

	const client = await Client.tryFind(clientId);

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
			const iat = await InitialAccessToken.find(
				readBearer(token, undefined, false),
				{ error: new InvalidToken('initial access token not found') }
			);
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

	const issueRegistrationAccessToken =
		ApplicationConfig['registration.issueRegistrationAccessToken'];
	let properties: Body = {};
	const clientId = idFactory({ oidc });

	let rat;

	if (
		issueRegistrationAccessToken === true ||
		(typeof issueRegistrationAccessToken === 'function' &&
			issueRegistrationAccessToken({ oidc }))
	) {
		rat = new RegistrationAccessToken({ clientId });
		oidc.entity('RegistrationAccessToken', rat);
	}

	Object.assign(properties, requestBody, {
		client_id: clientId,
		client_id_issued_at: epochTime()
	});
	properties = snakeToCanonical(properties);
	/*
	 * Marked as created on the client's own request, which is what lets the console tell it apart from
	 * one an administrator made. Set after the wire translation so it cannot be supplied by the caller:
	 * a registration body claiming `registered_dynamically: false` would otherwise be believed.
	 *
	 * There is deliberately no per-project acceptance check here, and the absence is a decision rather
	 * than an omission. A registration request names no project — RFC 7591 has no field for one — so a
	 * per-project rule could only rest on a project-scoped registration endpoint, which would hand an
	 * unauthenticated caller an oracle for which projects exist. The association this client needs is
	 * supplied at authorization time instead, from the declared resource the request names
	 * (`resolveBucketForRequest`), which is the same rule a document-identified client follows.
	 */
	properties.registeredDynamically = true;

	/*
	 * Housekeeping, here because this is the only moment that both correlates with growth and is
	 * already paying for a write. Registrations that were never taken up go; one that completed an
	 * authorization is untouched, whatever its age. See lib/models/client/dynamic_registration.ts for
	 * why this is a sweep rather than an expiry index.
	 */
	await reclaimUnusedRegistrations();

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

	const client = await addClient(properties, { store: true });
	oidc.entity('Client', client);

	const responseBody: Body = canonicalToSnake(client.metadata());

	if (rat) {
		Object.assign(responseBody, {
			registration_client_uri: oidc.urlFor('client', { clientId }),
			registration_access_token: await rat.save()
		});
	}

	set.status = 201;
	eventBus.emit('registration_create.success', { oidc }, client);

	return responseBody;
}

async function read({ params, headers, query, set }) {
	setBearerRealm(set);
	const oidc = new OIDCContext<Body>({}, headers, 'registration');
	const token = readBearer(headers.authorization, query, true);
	const { client } = await authenticate(oidc, params.clientId, token);

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

	const secretRequired = !client.clientSecret && Client.needsSecret(properties);

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

	const nextClient = await addClient(properties, { store: true });

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
		const rat = new RegistrationAccessToken({
			client,
			policies: regAccessToken.payload.policies
		});

		await regAccessToken.destroy();

		oidc.entity('RegistrationAccessToken', rat);
		responseBody.registration_access_token = await rat.save();
	}

	eventBus.emit('registration_update.success', { oidc }, nextClient);

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

	await Client.adapter.destroy(client.clientId);
	await regAccessToken.destroy();

	set.status = 204;
	eventBus.emit('registration_delete.success', { oidc }, client);
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
