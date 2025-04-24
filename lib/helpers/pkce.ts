import crypto from 'node:crypto';

import { InvalidGrant, InvalidRequest } from './errors.ts';
import constantEquals from './constant_equals.ts';
import { AuthorizationParameters } from '../consts/param_list.ts';

function verifyPKCECode(input: string, param: string) {
	if (input.length < 43 || input.length > 128) {
		throw new InvalidRequest(
			`${param} must be a string with a minimum 43 and maximum 128 length characters`
		);
	}

	if (/[^\w.\-~]/.test(input)) {
		throw new InvalidRequest(`${param} contains invalid characters`);
	}
}

export function authorizationPKCE(params: {
	code_challenge?: string | undefined;
	code_challenge_method?: string | undefined;
	response_type: string;
}) {
	if (params.response_type !== 'code') {
		return;
	}

	if (!params.code_challenge) {
		throw new InvalidRequest(
			'Authorization Server policy requires PKCE to be used for this request'
		);
	}
	if (!params.code_challenge_method) {
		throw new InvalidRequest('code_challenge_method must be provided');
	}
	if (params.code_challenge_method !== 'S256') {
		throw new InvalidRequest('not supported value of code_challenge_method');
	}
	verifyPKCECode(params.code_challenge, 'code_challenge');
}

export function verifyPKCE(
	verifier: string,
	challenge: string,
	method: string
) {
	if (verifier) {
		verifyPKCECode(verifier, 'code_verifier');
	}

	if (verifier || challenge) {
		try {
			let expected = verifier;
			if (!expected) throw new Error();

			if (method === 'S256') {
				expected = crypto.hash('sha256', expected, 'base64url');
			} else {
				throw new Error();
			}

			if (!constantEquals(challenge, expected)) {
				throw new Error();
			}
		} catch (err) {
			throw new InvalidGrant('PKCE verification failed');
		}
	}
}
