import * as JWT from '../../helpers/jwt.ts';
import instance from '../../helpers/weak_cache.ts';
import {
	InvalidRequest,
	InvalidRequestObject,
	OIDCProviderError
} from '../../helpers/errors.ts';
import { getSchemaValidator, TSchema, ValidationError } from 'elysia';
import { ISSUER } from 'lib/configs/env.js';
import { clockTolerance } from 'lib/configs/liveTime.js';

export function isEncryptedJWT(jwt: string): boolean {
	// Encrypted JWTs have 5 parts, while signed JWTs have 3
	return jwt.split('.').length === 5;
}

/*
 * Decrypts and validates the content of provided request parameter and replaces the parameters
 * provided via OAuth2.0 authorization request with these
 */
export default async function processRequestObject(
	schema: TSchema,
	ctx,
	{ clientAlg }: { clientAlg?: string } = {}
) {
	const { params, client, route } = ctx.oidc;

	const pushedRequestObject = 'PushedAuthorizationRequest' in ctx.oidc.entities;
	const isBackchannelAuthentication = route === 'backchannel_authentication';
	const { configuration, features } = instance(ctx.oidc.provider);

	if (params.request === undefined && client.requireSignedRequestObject) {
		throw new InvalidRequest('Request Object must be used by this client');
	}

	if (params.request === undefined) {
		return;
	}

	let trusted = false; // signed or encrypted by client confidential material

	if (features.encryption.enabled && isEncryptedJWT(params.request)) {
		try {
			const header = JWT.header(params.request);

			if (
				!configuration.requestObjectEncryptionAlgValues.includes(header.alg)
			) {
				throw new TypeError('unsupported encrypted request alg');
			}
			if (
				!configuration.requestObjectEncryptionEncValues.includes(header.enc)
			) {
				throw new TypeError('unsupported encrypted request enc');
			}

			let decrypted;
			if (/^(A|dir$)/.test(header.alg)) {
				client.checkClientSecretExpiration(
					'could not decrypt the Request Object - the client secret used for its encryption is expired',
					'invalid_request_object'
				);
				decrypted = await JWT.decrypt(params.request, client.symmetricKeyStore);
				trusted = true;
			} else {
				decrypted = await JWT.decrypt(
					params.request,
					instance(ctx.oidc.provider).keystore
				);
			}

			params.request = decrypted.toString('utf8');

			if (ctx.oidc.body) {
				ctx.oidc.body.request = params.request;
			}
		} catch (err) {
			if (err instanceof OIDCProviderError) {
				throw err;
			}

			throw new InvalidRequestObject(
				'could not decrypt request object',
				err.message
			);
		}
	}

	let decoded;

	try {
		decoded = JWT.decode(params.request);
	} catch (err) {
		throw new InvalidRequestObject(
			'could not parse Request Object',
			err.message
		);
	}

	const {
		payload,
		header: { alg }
	} = decoded;

	const validator = getSchemaValidator(schema);
	if (!validator.Check(payload)) {
		throw new ValidationError('requestObject', validator, payload);
	}

	const request = payload;
	const original = {};
	for (const param of ['state', 'response_mode', 'response_type']) {
		original[param] = params[param];
		if (request[param] !== undefined) {
			params[param] = request[param];
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
		if (request.client_id !== ctx.oidc.client.clientId) {
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

	if (
		!pushedRequestObject &&
		!configuration.requestObjectSigningAlgValues.includes(alg)
	) {
		throw new InvalidRequestObject('unsupported signed request alg');
	}

	const prop = isBackchannelAuthentication
		? 'backchannelAuthenticationRequestSigningAlg'
		: 'requestObjectSigningAlg';
	if (!pushedRequestObject && client[prop] && alg !== client[prop]) {
		throw new InvalidRequestObject(
			'the preregistered alg must be used in request or request_uri'
		);
	}

	const opts = {
		issuer: client.clientId,
		audience: ISSUER,
		clockTolerance
	};

	try {
		JWT.assertPayload(payload, opts);
	} catch (err) {
		throw new InvalidRequestObject(
			'Request Object claims are invalid',
			err.message
		);
	}

	await features.requestObjects.assertJwtClaimsAndHeader(
		ctx,
		structuredClone(decoded.payload),
		structuredClone(decoded.header),
		client
	);

	if (pushedRequestObject) {
		({ trusted } = pushedRequestObject);
	} else {
		try {
			if (alg.startsWith('HS')) {
				client.checkClientSecretExpiration(
					'could not validate the Request Object - the client secret used for its signature is expired',
					'invalid_request_object'
				);
				await JWT.verify(params.request, client.symmetricKeyStore, opts);
			} else {
				await JWT.verify(params.request, client.asymmetricKeyStore, opts);
			}
			trusted = true;
		} catch (err) {
			if (err instanceof OIDCProviderError) {
				throw err;
			}

			throw new InvalidRequestObject(
				'could not validate Request Object',
				err.message
			);
		}
	}

	if (trusted) {
		ctx.oidc.trusted = Object.keys(request);
	}

	params.request = undefined;

	const keys = new Set([...Object.keys(request), ...Object.keys(params)]);
	keys.forEach((key) => {
		if (key in request) {
			// use value from Request Object
			params[key] = request[key];
		} else {
			// ignore all OAuth 2.0 parameters outside of Request Object
			params[key] = undefined;
		}
	});

	if (
		pushedRequestObject &&
		ctx.oidc.entities.PushedAuthorizationRequest.dpopJkt
	) {
		params.dpop_jkt = ctx.oidc.entities.PushedAuthorizationRequest.dpopJkt;
		ctx.oidc.trusted?.push('dpop_jkt');
	}
}
