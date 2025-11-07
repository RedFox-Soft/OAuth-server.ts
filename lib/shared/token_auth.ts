import { InvalidRequest, InvalidClientAuth } from '../helpers/errors.ts';
import * as JWT from '../helpers/jwt.ts';
import instance from '../helpers/weak_cache.ts';
import certificateThumbprint from '../helpers/certificate_thumbprint.ts';
import { noVSCHAR } from '../consts/client_attributes.ts';

import { tokenJwtAuth } from './token_jwt_auth.js';
import { Client } from 'lib/models/client.js';
import { clientAuthSigningAlgValues } from 'lib/configs/jwaAlgorithms.js';
import { type Static, t } from 'elysia';
import { provider } from 'lib/provider.js';

const assertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

export const authParams = t.Object({
	client_id: t.Optional(t.String()),
	client_assertion: t.Optional(t.String()),
	client_assertion_type: t.Optional(t.String()),
	client_secret: t.Optional(t.String())
});

type authParamsType = Static<typeof authParams>;

// see https://tools.ietf.org/html/rfc6749#appendix-B
function decodeAuthToken(token: string): string {
	const authToken = decodeURIComponent(token.replace(/\+/g, '%20'));
	if (noVSCHAR.test(authToken)) {
		throw new Error('invalid character found');
	}
	return authToken;
}

type authorizationObject = {
	clientId: string;
	clientSecret?: string;
	methods: string[];
};

function findClientId(
	params: authParamsType,
	authorization?: string
): authorizationObject {
	const {
		client_id: clientId,
		client_assertion: clientAssertion,
		client_assertion_type: clientAssertionType,
		client_secret: clientSecret
	} = params;

	const res: authorizationObject = { clientId: '', methods: [] };

	if (authorization !== undefined) {
		const parts = authorization.split(' ');
		if (parts.length !== 2 || parts[0].toLowerCase() !== 'basic') {
			throw new InvalidRequest('invalid authorization header value format');
		}

		const basic = Buffer.from(parts[1], 'base64').toString('utf8');
		const i = basic.indexOf(':');

		if (i === -1) {
			throw new InvalidRequest('invalid authorization header value format');
		}

		try {
			res.clientId = decodeAuthToken(basic.slice(0, i));
			res.clientSecret = decodeAuthToken(basic.slice(i + 1));
		} catch {
			throw new InvalidRequest(
				'client_id and client_secret in the authorization header are not properly encoded'
			);
		}

		if (clientId !== undefined && res.clientId !== clientId) {
			throw new InvalidRequest('mismatch in body and authorization client ids');
		}

		if (!res.clientSecret) {
			throw new InvalidRequest(
				'client_secret must be provided in the Authorization header'
			);
		}

		if (clientSecret !== undefined) {
			throw new InvalidRequest(
				'client authentication must only be provided using one mechanism'
			);
		}

		res.methods = ['client_secret_basic', 'client_secret_post'];
	} else if (clientId !== undefined) {
		res.clientId = clientId;
		res.methods = clientSecret
			? ['client_secret_basic', 'client_secret_post']
			: ['none', 'tls_client_auth', 'self_signed_tls_client_auth'];
	}

	if (clientAssertion !== undefined) {
		if (clientSecret !== undefined || authorization !== undefined) {
			throw new InvalidRequest(
				'client authentication must only be provided using one mechanism'
			);
		}

		let sub;
		try {
			({
				payload: { sub }
			} = JWT.decode(clientAssertion));
		} catch {
			throw new InvalidRequest('invalid client_assertion format');
		}

		if (!sub) {
			throw new InvalidClientAuth(
				'sub (JWT subject) must be provided in the client_assertion JWT'
			);
		}

		if (clientId && sub !== clientId) {
			throw new InvalidRequest(
				'subject of client_assertion must be the same as client_id provided in the body'
			);
		}

		if (clientAssertionType === undefined) {
			throw new InvalidRequest('client_assertion_type must be provided');
		}

		if (clientAssertionType !== assertionType) {
			throw new InvalidRequest(
				`client_assertion_type must have value ${assertionType}`
			);
		}

		res.clientId = sub;
		res.methods = ['client_secret_jwt', 'private_key_jwt'];
	}

	if (!res.clientId) {
		throw new InvalidRequest('no client authentication mechanism provided');
	}
	return res;
}

export async function tokenAuth(ctx) {
	const { features } = instance(provider);

	const auth = findClientId(ctx.oidc.params, ctx.headers?.authorization);

	const client = await Client.find(auth.clientId);
	if (!client) {
		throw new InvalidClientAuth('client not found');
	}

	ctx.oidc.entity('Client', client);

	const {
		params,
		client: { clientAuthMethod, clientAuthSigningAlg }
	} = ctx.oidc;

	if (!auth.methods.includes(clientAuthMethod)) {
		throw new InvalidClientAuth(
			'the provided authentication mechanism does not match the registered client authentication method'
		);
	}

	switch (clientAuthMethod) {
		case 'none':
			break;

		case 'client_secret_basic':
		case 'client_secret_post': {
			ctx.oidc.client.checkClientSecretExpiration(
				'could not authenticate the client - its client secret is expired'
			);
			const actual = params.client_secret || auth.clientSecret;
			const matches = await ctx.oidc.client.compareClientSecret(actual);
			if (!matches) {
				throw new InvalidClientAuth('invalid secret provided');
			}

			break;
		}

		case 'client_secret_jwt':
			ctx.oidc.client.checkClientSecretExpiration(
				'could not authenticate the client - its client secret used for the client_assertion is expired'
			);
			await tokenJwtAuth(
				ctx,
				ctx.oidc.client.symmetricKeyStore,
				clientAuthSigningAlg
					? [clientAuthSigningAlg]
					: clientAuthSigningAlgValues.filter((alg) => alg.startsWith('HS'))
			);

			break;

		case 'private_key_jwt':
			await tokenJwtAuth(
				ctx,
				ctx.oidc.client.asymmetricKeyStore,
				clientAuthSigningAlg
					? [clientAuthSigningAlg]
					: clientAuthSigningAlgValues.filter((alg) => !alg.startsWith('HS'))
			);

			break;

		case 'tls_client_auth': {
			const {
				getCertificate,
				certificateAuthorized,
				certificateSubjectMatches
			} = features.mTLS;

			const cert = getCertificate(ctx);

			if (!cert) {
				throw new InvalidClientAuth('client certificate was not provided');
			}

			if (!certificateAuthorized(ctx)) {
				throw new InvalidClientAuth('client certificate was not verified');
			}

			for (const [prop, key] of Object.entries({
				tlsClientAuthSubjectDn: 'tls_client_auth_subject_dn',
				tlsClientAuthSanDns: 'tls_client_auth_san_dns',
				tlsClientAuthSanIp: 'tls_client_auth_san_ip',
				tlsClientAuthSanEmail: 'tls_client_auth_san_email',
				tlsClientAuthSanUri: 'tls_client_auth_san_uri'
			})) {
				const value = ctx.oidc.client[prop];
				if (value) {
					if (!certificateSubjectMatches(ctx, key, value)) {
						throw new InvalidClientAuth(
							'certificate subject value does not match the registered one'
						);
					}
					break;
				}
			}

			break;
		}
		case 'self_signed_tls_client_auth': {
			const { getCertificate } = features.mTLS;
			const cert = getCertificate(ctx);

			if (!cert) {
				throw new InvalidClientAuth('client certificate was not provided');
			}

			await ctx.oidc.client.asymmetricKeyStore.refresh();
			const expected = certificateThumbprint(cert);
			const match = [...ctx.oidc.client.asymmetricKeyStore].find(
				({ 'x5t#S256': actual }) => actual === expected
			);

			if (!match) {
				throw new InvalidClientAuth('unregistered client certificate provided');
			}

			break;
		}
	}
}
