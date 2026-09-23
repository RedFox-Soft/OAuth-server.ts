import crypto from 'node:crypto';

import { ApplicationConfig } from '../configs/application.js';
import { InvalidGrant, InvalidRequest } from './errors.js';
import constantEquals from './constant_equals.js';

export function authorizationPKCE(oidc: {
	params: {
		code_challenge?: string | undefined;
		code_challenge_method?: string | undefined;
		response_type?: string;
	};
	client?: { tokenEndpointAuthMethod?: string } | undefined;
}) {
	const params = oidc.params;

	if (params.response_type !== 'code') {
		return;
	}

	/*
	 * OAuth 2.1 §7.5.1.1 lifts the demand for a confidential client only, so a client presenting no
	 * credentials at the token endpoint proves possession whatever the policy says — which is what
	 * stops a conformance setting weakening this server's own public console and agent clients.
	 *
	 * A method without a challenge is refused in both states: that client meant to send a proof and
	 * got it wrong, and accepting it would hand it an unbound code it believes is bound.
	 */
	const mayOmitProof =
		!ApplicationConfig['pkce.required'] &&
		oidc.entities.Client?.tokenEndpointAuthMethod !== 'none' &&
		!params.code_challenge_method;

	if (!params.code_challenge) {
		if (mayOmitProof) {
			return;
		}

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
}

export function verifyPKCE(
	verifier?: string,
	challenge?: string,
	method?: string
) {
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
		} catch {
			throw new InvalidGrant('PKCE verification failed');
		}
	}
}
