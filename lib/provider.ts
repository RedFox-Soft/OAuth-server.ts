import EventEmitter from 'node:events';

import QuickLRU from 'quick-lru';

import Configuration from './helpers/configuration.ts';
import * as instance from './helpers/weak_cache.ts';
import initializeApp from './helpers/initialize_app.ts';
import initializeClients from './helpers/initialize_clients.ts';
import ResourceServer from './helpers/resource_server.ts';
import { OIDCProviderError } from './helpers/errors.ts';
import * as models from './models/index.ts';
import { globalConfiguration } from './globalConfiguration.js';
import { Client } from './models/client.js';
import { IdToken } from './models/id_token.js';
import { JWKS_KEYS } from './configs/env.js';
import KeyStore from './helpers/keystore.js';

class ProviderClass extends EventEmitter {
	#ClientCredentials;

	#BackchannelAuthenticationRequest;

	#Grant;

	#InitialAccessToken;

	#RegistrationAccessToken;

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

		this.#int.configuration = globalConfiguration;
		this.#int.features = globalConfiguration.features;

		this.#int.responseModes = new Map();
		this.#int.grantTypeHandlers = new Map();

		const keystore = new KeyStore();
		JWKS_KEYS.forEach((key) => keystore.add(structuredClone(key)));

		this.#int.keystore = keystore;
		const keys = [...keystore].map((key) => ({
			kty: key.kty,
			use: key.use,
			key_ops: key.key_ops ? [...key.key_ops] : undefined,
			kid: key.kid,
			alg: key.alg,
			crv: key.crv,
			e: key.e,
			n: key.n,
			x: key.x,
			x5c: key.x5c ? [...key.x5c] : undefined,
			y: key.y
		}));
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

	registerGrantType(name, handler) {
		this.#int.configuration.grantTypes.add(name);
		const { grantTypeHandlers } = this.#int;
		grantTypeHandlers.set(name, handler);
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
			// eslint-disable-next-line no-param-reassign
			request = await this.BackchannelAuthenticationRequest.find(request, {
				ignoreExpiration: true
			});
			if (!request) {
				throw new Error('BackchannelAuthenticationRequest not found');
			}
		} else if (!(request instanceof this.BackchannelAuthenticationRequest)) {
			throw new TypeError('invalid "request" argument');
		}

		const client = await Client.find(request.clientId);
		if (!client) {
			throw new Error('Client not found');
		}

		if (typeof result === 'string' && result) {
			// eslint-disable-next-line no-param-reassign
			result = await this.Grant.find(result);
			if (!result) {
				throw new Error('Grant not found');
			}
		}

		switch (true) {
			case result instanceof this.Grant:
				if (request.clientId !== result.clientId) {
					throw new Error('client mismatch');
				}

				if (request.accountId !== result.accountId) {
					throw new Error('accountId mismatch');
				}

				Object.assign(request, {
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
				Object.assign(request, {
					error: result.error,
					error_description: result.error_description
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

	get IdToken() {
		return IdToken;
	}

	get Client() {
		return Client;
	}

	get Grant() {
		this.#Grant ||= models.getGrant(this);
		return this.#Grant;
	}

	get ClientCredentials() {
		this.#ClientCredentials ||= models.getClientCredentials(this);
		return this.#ClientCredentials;
	}

	get InitialAccessToken() {
		this.#InitialAccessToken ||= models.getInitialAccessToken(this);
		return this.#InitialAccessToken;
	}

	get RegistrationAccessToken() {
		this.#RegistrationAccessToken ||= models.getRegistrationAccessToken(this);
		return this.#RegistrationAccessToken;
	}

	get BackchannelAuthenticationRequest() {
		this.#BackchannelAuthenticationRequest ||=
			models.getBackchannelAuthenticationRequest(this);
		return this.#BackchannelAuthenticationRequest;
	}

	get ResourceServer() {
		return ResourceServer;
	}
}

export const provider = new ProviderClass();
