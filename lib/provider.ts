import EventEmitter from 'node:events';
import * as crypto from 'node:crypto';

import QuickLRU from 'quick-lru';

import { ApplicationConfig } from './configs/application.js';

const SIG_ALGS = new Set([
	'RS256',
	'RS384',
	'RS512',
	'PS256',
	'PS384',
	'PS512',
	'ES256',
	'ES256K',
	'ES384',
	'ES512',
	'EdDSA',
	'Ed25519',
	'HS256',
	'HS384',
	'HS512'
]);

// RFC 7638 JWK thumbprint over the required members (already in lexicographic order per kty).
function jwkThumbprint(key) {
	let members;
	switch (key.kty) {
		case 'RSA':
			members = { e: key.e, kty: key.kty, n: key.n };
			break;
		case 'EC':
			members = { crv: key.crv, kty: key.kty, x: key.x, y: key.y };
			break;
		case 'OKP':
			members = { crv: key.crv, kty: key.kty, x: key.x };
			break;
		default:
			return undefined;
	}
	return crypto.hash('sha256', JSON.stringify(members), 'base64url');
}

function sigAlgForKey(key) {
	if (key.kty === 'EC') {
		switch (key.crv) {
			case 'P-256':
				return 'ES256';
			case 'P-384':
				return 'ES384';
			case 'P-521':
				return 'ES512';
			default:
				return undefined;
		}
	}
	if (key.kty === 'OKP' && key.crv === 'Ed25519') {
		return 'EdDSA';
	}
	return undefined;
}

import Configuration from './helpers/configuration.ts';
import * as instance from './helpers/weak_cache.ts';
import initializeApp from './helpers/initialize_app.ts';
import initializeClients from './helpers/initialize_clients.ts';
import { OIDCProviderError } from './helpers/errors.ts';
import { BackchannelAuthenticationRequest } from './models/backchannel_authentication_request.js';
import { Client } from './models/client.js';
import { JWKS_KEYS } from './configs/keys.js';
import KeyStore from './helpers/keystore.js';
import { Grant } from './models/grant.js';

class ProviderClass extends EventEmitter {
	#int = {};

	constructor() {
		super();
		this.init({});
	}

	init(setup) {
		const configuration = new Configuration(setup);
		this.#int.staticClients = new Map();
		this.#int.dynamicClients = new QuickLRU({ maxSize: 100 });

		instance.set(this, this.#int);

		this.#int.configuration = configuration;
		this.#int.features = configuration.features;

		this.#int.responseModes = new Map();

		const keystore = new KeyStore();
		// Honor a per-instance JWKS supplied via configuration; fall back to the environment keys.
		const configuredKeys = setup?.jwks?.keys ?? JWKS_KEYS;
		configuredKeys.forEach((key) => keystore.add(structuredClone(key)));

		this.#int.keystore = keystore;
		// Publish the public JWKS, normalizing each key: derive kid (RFC 7638 thumbprint) and use.
		// When encryption is disabled every key is signing-only (use: 'sig', with a concrete alg
		// derived for EC/OKP); when enabled, use is only inferred from an explicit alg.
		const encryptionEnabled = Boolean(ApplicationConfig['encryption.enabled']);
		const keys = [...keystore].map((key) => {
			let { alg, use } = key;
			if (alg) {
				use ??= SIG_ALGS.has(alg) ? 'sig' : 'enc';
			} else if (!encryptionEnabled) {
				use ??= 'sig';
				alg ??= sigAlgForKey(key);
			}
			return {
				kty: key.kty,
				use,
				key_ops: key.key_ops ? [...key.key_ops] : undefined,
				kid: key.kid ?? jwkThumbprint(key),
				alg,
				crv: key.crv,
				e: key.e,
				n: key.n,
				x: key.x,
				x5c: key.x5c ? [...key.x5c] : undefined,
				y: key.y
			};
		});
		this.#int.jwks = { keys };

		delete configuration.jwks;

		initializeApp.call(this);

		initializeClients.call(this, configuration.clients);
		delete configuration.clients;
		return this;
	}

	urlFor(name, opt) {
		return new URL(this.pathFor(name, opt), this.issuer).href;
	}

	registerResponseMode(name, handler) {
		const { responseModes } = this.#int;
		if (!responseModes.has(name)) {
			responseModes.set(name, handler.bind(this));
		}
	}

	pathFor(name, { mountPath = '', ...opts } = {}) {
		const routerUrl = this.#int.router.url(name, opts);

		if (routerUrl instanceof Error) {
			throw routerUrl;
		}

		return [mountPath, routerUrl].join('');
	}

	async backchannelResult(
		request,
		result,
		{ acr, amr, authTime, sessionUid, expiresWithSession, sid } = {}
	) {
		if (typeof request === 'string' && request) {
			request = await BackchannelAuthenticationRequest.find(request, {
				ignoreExpiration: true
			});
			if (!request) {
				throw new Error('BackchannelAuthenticationRequest not found');
			}
		} else if (!(request instanceof BackchannelAuthenticationRequest)) {
			throw new TypeError('invalid "request" argument');
		}

		const client = await Client.find(request.payload.clientId);
		if (!client) {
			throw new Error('Client not found');
		}

		if (typeof result === 'string' && result) {
			result = await Grant.find(result);
			if (!result) {
				throw new Error('Grant not found');
			}
		}

		switch (true) {
			case result instanceof Grant:
				if (request.payload.clientId !== result.payload.clientId) {
					throw new Error('client mismatch');
				}

				if (request.payload.accountId !== result.payload.accountId) {
					throw new Error('accountId mismatch');
				}

				Object.assign(request.payload, {
					grantId: result.jti,
					acr,
					amr,
					authTime,
					sessionUid,
					expiresWithSession,
					sid
				});
				break;
			case result instanceof OIDCProviderError:
				Object.assign(request.payload, {
					error: result.error,
					errorDescription: result.error_description
				});
				break;
			default:
				throw new TypeError('invalid "result" argument');
		}

		await request.save();

		if (client.backchannelTokenDeliveryMode === 'ping') {
			await client.backchannelPing(request);
		}
	}

}

export const provider = new ProviderClass();
