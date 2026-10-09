import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
import * as JWT from '../../helpers/jwt.ts';
import { keysFor } from 'lib/keys/issuer_keys.js';
import { clientKeys, checkClientSecretExpiration } from 'lib/models/client.js';
import { assertJwtClaimsAndHeader } from '../../addon/index.js';
import {
	InvalidRequest,
	InvalidRequestObject,
	OIDCProviderError
} from '../../helpers/errors.ts';
import {
	getSchemaValidator,
	mapValueError,
	type TSchema,
	ValidationError
} from 'elysia';
import { JWTparameters } from 'lib/consts/param_list.js';
import {
	declaredParams,
	ignoreUnknownIn
} from 'lib/plugins/ignore_unknown_params.js';
import { issuerFor } from 'lib/configs/issuer.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { clockTolerance } from 'lib/configs/liveTime.js';
import {
	requestObjectEncryptionAlgValues,
	requestObjectEncryptionEncValues,
	requestObjectSigningAlgValues
} from 'lib/configs/jwaAlgorithms.js';

export function isEncryptedJWT(jwt: string): boolean {
	// Encrypted JWTs have 5 parts, while signed JWTs have 3
	return jwt.split('.').length === 5;
}

// Whether a JOSE header member is one of the values this server supports.
function isOneOf<T extends string>(
	values: readonly T[],
	value: unknown
): value is T {
	return values.some((allowed) => allowed === value);
}

function messageOf(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}

// The members whose refusal is a refusal of the Request Object itself rather than of a parameter.
const OBJECT_MEMBERS = new Set([
	...Object.keys(JWTparameters.properties),
	'request',
	'request_uri'
]);

/*
 * K appears once in the signature but is what types the body: it ties the read and the write to one
 * member. With a plain `keyof PipelineParams` key the write would have to suit every member at once,
 * which only undefined does, and the checker refuses the assignment.
 */
// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-parameters -- see above
function copyParam<K extends keyof PipelineParams>(
	target: PipelineParams,
	source: PipelineParams,
	key: K
) {
	target[key] = source[key];
}

/*
 * Decrypts and validates the content of provided request parameter and replaces the parameters
 * provided via OAuth2.0 authorization request with these
 */
export default async function processRequestObject(
	// An endpoint's object schema: validated against, and read for the names it declares.
	schema: TSchema & { readonly properties: Record<string, unknown> },
	oidc: OIDCContext<PipelineParams>,
	{
		isPar = false,
		trusted = false
	}: { isPar?: boolean; trusted?: boolean } = {}
) {
	const { params, client, route } = oidc;

	const pushedRequestObject = isPar;
	const isBackchannelAuthentication = route === 'backchannel_authentication';

	if (
		params.request === undefined &&
		(client.requireSignedRequestObject ||
			(isBackchannelAuthentication &&
				client['requestObject.backChannelSigningAlg']))
	) {
		throw new InvalidRequest('Request Object must be used by this client');
	}

	if (params.request === undefined) {
		return;
	}

	if (
		ApplicationConfig['encryption.enabled'] &&
		isEncryptedJWT(params.request)
	) {
		try {
			const header = JWT.header(params.request);

			if (!isOneOf(requestObjectEncryptionAlgValues(), header.alg)) {
				throw new TypeError('unsupported encrypted request alg');
			}
			if (!isOneOf(requestObjectEncryptionEncValues, header.enc)) {
				throw new TypeError('unsupported encrypted request enc');
			}

			let decrypted;
			if (/^(A|dir$)/.test(header.alg)) {
				checkClientSecretExpiration(
					client,
					'could not decrypt the Request Object - the client secret used for its encryption is expired',
					'invalid_request_object'
				);
				decrypted = await JWT.decrypt(
					params.request,
					clientKeys(client).symmetric
				);
				trusted = true;
			} else {
				// Only the addressed issuer's own keys: a request object encrypted to another bucket's key
				// was meant for that bucket.
				decrypted = await JWT.decrypt(
					params.request,
					(await keysFor(oidc.bucket)).decryption
				);
			}

			params.request = decrypted.toString('utf8');
		} catch (err) {
			if (err instanceof OIDCProviderError) {
				throw err;
			}

			throw new InvalidRequestObject(
				'could not decrypt request object',
				messageOf(err)
			);
		}
	}

	let decoded;

	try {
		decoded = JWT.decode(params.request);
	} catch (err) {
		throw new InvalidRequestObject(
			'could not parse Request Object',
			messageOf(err)
		);
	}

	const { payload } = decoded;
	const alg =
		typeof decoded.header.alg === 'string' ? decoded.header.alg : undefined;

	/*
	 * RFC 9101 §4: "The Request Object MAY include any extension parameters." A closed schema turns
	 * that permission into invalid_request, so the extras are dropped here and the declared members
	 * are what gets checked — the same ignore rule the endpoints themselves live under, one level in.
	 */
	ignoreUnknownIn(declaredParams(schema), payload);

	const validator = getSchemaValidator(schema);
	if (!validator.Check(payload)) {
		const refusal = new ValidationError('requestObject', validator, payload);
		const first = mapValueError(refusal.valueError);
		/*
		 * A registered claim of the object that is missing or malformed, or a `request`/`request_uri`
		 * nested inside it, makes the *object* invalid: RFC 9101 §6.2's invalid_request_object. An
		 * authorization parameter carried inside it is judged as that parameter, as if it had arrived
		 * beside it — a `plain` code_challenge_method is still RFC 7636 §4.4.1's invalid_request, and
		 * `registration` still registration_not_supported. The conformance suite holds both halves:
		 * `ensure-request-object-without-exp-fails` and `par-authorization-request-containing-request_uri`
		 * on one side, `par-plain-pkce-rejected` on the other.
		 */
		const member = first?.path.split('/')[1];
		if (member !== undefined && OBJECT_MEMBERS.has(member)) {
			const described: unknown = first?.schema.error;
			throw new InvalidRequestObject(
				typeof described === 'string' && described
					? described
					: first?.summary || 'Request Object is invalid'
			);
		}
		throw refusal;
	}

	// Validated just above against this endpoint's own request schema, whose members are pipeline parameters.
	const request = payload as PipelineParams;
	const original: PipelineParams = {};
	for (const param of ['state', 'response_mode', 'response_type'] as const) {
		copyParam(original, params, param);
		if (request[param] !== undefined) {
			copyParam(params, request, param);
		}
	}

	if (
		original.response_type &&
		request.response_type !== undefined &&
		request.response_type !== original.response_type
	) {
		throw new InvalidRequestObject(
			'request response_type must equal the one in request parameters'
		);
	}

	if (
		params.client_id &&
		request.client_id !== undefined &&
		request.client_id !== params.client_id
	) {
		throw new InvalidRequestObject(
			'request client_id must equal the one in request parameters'
		);
	}

	if (route === '/par') {
		if (request.client_id !== oidc.client.clientId) {
			throw new InvalidRequestObject(
				"request client_id must equal the authenticated client's client_id"
			);
		}
	}

	if (
		request.client_id !== undefined &&
		request.client_id !== client.clientId
	) {
		throw new InvalidRequestObject('request client_id mismatch');
	}

	if (!pushedRequestObject && !isOneOf(requestObjectSigningAlgValues, alg)) {
		throw new InvalidRequestObject('unsupported signed request alg');
	}

	const prop = isBackchannelAuthentication
		? 'requestObject.backChannelSigningAlg'
		: 'requestObject.signingAlg';
	if (!pushedRequestObject && client[prop] && alg !== client[prop]) {
		throw new InvalidRequestObject(
			'the preregistered alg must be used in request or request_uri'
		);
	}

	/*
	 * The addressed issuer, not the instance's: a request object is meant for the authorization server it
	 * is sent to, and every bucket with an address is its own. Checked against the instance's identifier,
	 * an object audienced at `/acme` was refused at `/acme/par`. The pushed request PAR stores for an
	 * unsigned push carries the same audience (`pushed_authorization_request_response.ts`), so a
	 * `request_uri` one issuer handed out is not accepted by another.
	 */
	const opts = {
		issuer: client.clientId,
		audience: issuerFor(oidc.bucket),
		clockTolerance
	};

	try {
		JWT.assertPayload(payload, opts);
	} catch (err) {
		throw new InvalidRequestObject(
			'Request Object claims are invalid',
			messageOf(err)
		);
	}

	await assertJwtClaimsAndHeader(
		oidc,
		structuredClone(decoded.payload),
		structuredClone(decoded.header),
		client
	);

	/*
	 * A pushed request was verified when it was pushed, and whether it was trusted arrives in the
	 * `trusted` option. This branch used to destructure `trusted` out of the boolean `isPar`, which
	 * replaced the flag with `undefined` for every pushed request.
	 */
	if (!pushedRequestObject) {
		try {
			if (alg?.startsWith('HS')) {
				checkClientSecretExpiration(
					client,
					'could not validate the Request Object - the client secret used for its signature is expired',
					'invalid_request_object'
				);
				await JWT.verify(params.request, clientKeys(client).symmetric, opts);
			} else {
				await JWT.verify(params.request, clientKeys(client).asymmetric, opts);
			}
			trusted = true;
		} catch (err) {
			if (err instanceof OIDCProviderError) {
				throw err;
			}

			throw new InvalidRequestObject(
				'could not validate Request Object',
				messageOf(err)
			);
		}
	}

	if (trusted) {
		oidc.trusted = Object.keys(request);
	}

	const decryptedRequest = params.request;
	params.request = undefined;

	// `Object.keys` widens to string; every key comes from one of these two pipeline-parameter objects.
	const keys = new Set([
		...Object.keys(request),
		...Object.keys(params)
	] as (keyof PipelineParams)[]);
	keys.forEach((key) => {
		if (key in request) {
			// use value from Request Object
			copyParam(params, request, key);
		} else {
			// ignore all OAuth 2.0 parameters outside of Request Object
			params[key] = undefined;
		}
	});

	if (
		pushedRequestObject &&
		oidc.require('PushedAuthorizationRequest').payload.dpopJkt
	) {
		params.dpop_jkt = oidc.require(
			'PushedAuthorizationRequest'
		).payload.dpopJkt;
		oidc.trusted?.push('dpop_jkt');
	}
	return decryptedRequest;
}
