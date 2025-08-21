import als from '../helpers/als.ts';
import { BaseModel } from './base_model.js';
import { ttl } from '../configs/liveTime.js';
import { jwt } from './formats/jwt.js';

export class BaseToken extends BaseModel {
	#client;

	#resourceServer;

	constructor({ client, resourceServer, expiresIn, ...rest } = {}) {
		super(rest);
		if (typeof client !== 'undefined') {
			this.client = client;
		}
		if (typeof resourceServer !== 'undefined') {
			this.resourceServer = resourceServer;
		}
		if (typeof expiresIn !== 'undefined') {
			this.expiresIn = expiresIn;
		}
	}

	set client(client) {
		this.clientId = client.clientId;
		this.#client = client;
	}

	get client() {
		return this.#client;
	}

	set resourceServer(resourceServer) {
		this.setAudience(resourceServer.audience || resourceServer.identifier());
		this.#resourceServer = resourceServer;
	}

	get resourceServer() {
		return this.#resourceServer;
	}

	static expiresIn(...args) {
		if (this.name in ttl) {
			return ttl[this.name](...args);
		}
	}

	async save() {
		return super.save(this.remainingTTL);
	}

	static get IN_PAYLOAD() {
		return [...super.IN_PAYLOAD, 'clientId'];
	}

	get expiration() {
		if (!this.expiresIn) {
			this.expiresIn = this.constructor.expiresIn(
				als.getStore(),
				this,
				this.#client
			);
		}

		return this.expiresIn;
	}

	get scopes() {
		return new Set(this.scope?.split(' '));
	}

	get resourceIndicators() {
		return new Set(
			Array.isArray(this.resource) ? this.resource : [this.resource]
		);
	}

	generateTokenId() {
		const format = this.resourceServer?.accessTokenFormat ?? 'opaque';
		if (format === 'opaque') {
			return super.generateTokenId();
		}
		if (format !== 'jwt') {
			throw new Error('invalid format resolved');
		}
		return jwt.generateTokenId.call(this);
	}

	async getValueAndPayload() {
		const format = this.resourceServer?.accessTokenFormat ?? 'opaque';
		if (format === 'opaque') {
			return super.getValueAndPayload();
		}
		if (format !== 'jwt') {
			throw new Error('invalid format resolved');
		}
		return jwt.getValueAndPayload.call(this);
	}
}
