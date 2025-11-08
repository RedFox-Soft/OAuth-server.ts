import { provider } from 'lib/provider.js';
import instance from '../helpers/weak_cache.ts';
import { OIDCProviderError } from '../helpers/errors.ts';
import { getErrorHtmlResponse } from '../html/error.tsx';
import { routeNames } from 'lib/consts/param_list.js';
import {
	type Context,
	ErrorContext,
	mapValueError,
	ValidationError
} from 'elysia';
import { isAllowRedirectUri } from 'lib/actions/authorization/authorization.js';
import { ISSUER } from 'lib/configs/env.js';
import { dPoPSigningAlgValues } from 'lib/configs/jwaAlgorithms.js';
import { UseDpopNonce } from 'lib/helpers/validate_dpop.js';
import { DPoPNonces } from 'lib/helpers/dpop_nonces.js';

function getFirstError(error: ValidationError) {
	const firstError =
		'valueError' in error ? mapValueError(error.valueError) : error;
	return firstError;
}

export default function getWWWAuthenticate(
	authorization: string,
	isDpop: boolean,
	errorObj: { error: string; error_description?: string }
) {
	let scheme = '';
	if (authorization.startsWith('dpop') || isDpop) {
		scheme = 'DPoP';
	} else if (authorization.startsWith('bearer')) {
		scheme = 'Bearer';
	} else {
		return;
	}
	const obj = {
		realm: ISSUER,
		...errorObj,
		...(scheme === 'DPoP'
			? {
					algs: dPoPSigningAlgValues.join(' ')
				}
			: undefined)
	};

	const wwwAuth = Object.entries(obj)
		.map(([key, val]) => `${key}="${val.replace(/"/g, '\\"')}"`)
		.join(', ');

	return `${scheme} ${wwwAuth}`;
}

function getObjFromError(code: string, errorObj: any) {
	if (errorObj instanceof OIDCProviderError) {
		const { error, error_description } = errorObj;
		return { error, ...(error_description ? { error_description } : {}) };
	}
	if (code === 'VALIDATION') {
		const firstError = getFirstError(errorObj);
		if (firstError.schema.error) {
			const schemaError = firstError.schema.error;
			if (typeof schemaError === 'string') {
				return {
					error: 'invalid_request',
					error_description: firstError.schema.error
				};
			}
			return schemaError;
		}
		const error_description =
			mapValueError(firstError).summary || 'Validation error';
		return {
			error: 'invalid_request',
			error_description
		};
	}
	return {
		error: 'server_error',
		error_description: 'An unexpected error occurred'
	};
}

const mapErrorCode = {
	[routeNames.token]: 'grant.error',
	[routeNames.authorization]: 'authorization.error',
	[routeNames.device_authorization]: 'device_authorization.error',
	[routeNames.introspect]: 'introspection.error',
	[routeNames.userinfo]: 'userinfo.error'
};

export async function errorHandler(obj: ErrorContext) {
	const { set, route, code, request } = obj;
	let { error } = obj;
	if (set.status === 500) {
		provider.emit('server_error', error);
	} else {
		const key = mapErrorCode[route] ?? 'server_error';
		provider.emit(key, error);
	}

	if (route === routeNames.authorization && error.allow_redirect !== false) {
		try {
			return await authorizationErrorHandler(obj);
		} catch (e) {
			if (e instanceof OIDCProviderError) {
				error = e;
				const key = mapErrorCode[route] ?? 'server_error';
				provider.emit(key, error);
			} else {
				provider.emit('server_error', e);
			}
		}
	}

	const isOIDError = error instanceof OIDCProviderError;
	if (isOIDError) {
		set.status = error.status;
	}
	if (code === 'UNKNOWN' && !isOIDError) {
		console.error('Unknown error', error);
	}

	let errorObj = getObjFromError(code, error);
	if (isOIDError && error.status === 401) {
		const auth = request.headers.get('authorization')?.toLowerCase() ?? '';
		const isDpop = !!request.headers.get('dpop');
		const authError = getWWWAuthenticate(auth, isDpop, errorObj);
		if (authError) {
			set.headers['WWW-Authenticate'] = authError;
		}
	}
	if (isOIDError && error instanceof UseDpopNonce) {
		const dPoPInstance = DPoPNonces.fabrica();
		if (!dPoPInstance) {
			throw new Error('dpop.nonceSecret configuration is missing');
		}
		set.headers['DPoP-Nonce'] = dPoPInstance.nextNonce();
	}

	const accept = request.headers.get('accept') || '';
	if (accept.includes('text/html')) {
		return getErrorHtmlResponse(
			set.status,
			errorObj.error,
			errorObj.error_description
		);
	}
	return errorObj;
}

async function authorizationErrorHandler({
	code,
	error,
	query,
	body,
	request
}: Context) {
	if (error instanceof ValidationError) {
		const firstError = getFirstError(error);
		if (
			firstError.path === '/redirect_uri' ||
			firstError.path === '/client_id'
		) {
			throw error;
		}
	}

	const params = request.method === 'POST' ? body : query;
	const redirectObj = await isAllowRedirectUri(params);

	const state = redirectObj.state;
	const out = {
		...getObjFromError(code, error),
		...(state ? { state } : {}),
		iss: ISSUER
	};
	let mode = params.response_mode;
	if (!instance(provider).responseModes.has(mode)) {
		mode = 'query';
	}
	const handler = instance(provider).responseModes.get(mode);
	return await handler(redirectObj.ctx, redirectObj.redirect_uri, out);
}
