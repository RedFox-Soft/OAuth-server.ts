/*
 * What getResourceServerInfo answers for a resource indicator: the scopes it offers and, optionally, the
 * audience its tokens carry and how they look (opaque unless it says otherwise).
 */
import type { KeyObject } from 'node:crypto';

// A key a resource server's JWT access tokens are signed or encrypted with, as a deployment gives it.
// Raw bytes or a string are a secret, read as utf8 as crypto.createSecretKey does.
type ResourceServerKey = KeyObject | CryptoKey | Uint8Array | string;

// RFC 9068 JWT access tokens: how a resource server's tokens are signed and, optionally, encrypted.
export type ResourceServerJwt = {
	// false: encrypted only, not signed.
	sign?: { alg?: string; key?: ResourceServerKey; kid?: string } | false;
	encrypt?: {
		alg?: string;
		enc?: string;
		key?: ResourceServerKey;
		kid?: string;
	};
};

export type ResourceServerInfo = {
	scope: string;
	audience?: string;
	accessTokenFormat?: 'jwt' | 'opaque';
	accessTokenTTL?: number;
	jwt?: ResourceServerJwt;
};

export default class ResourceServer {
	private _identifier: string;
	audience: ResourceServerInfo['audience'];
	scope: ResourceServerInfo['scope'];
	accessTokenTTL: ResourceServerInfo['accessTokenTTL'];
	accessTokenFormat: ResourceServerInfo['accessTokenFormat'];
	jwt: ResourceServerInfo['jwt'];

	constructor(identifier: string, data: ResourceServerInfo) {
		this._identifier = identifier;
		this.audience = data.audience;
		this.scope = data.scope;
		this.accessTokenTTL = data.accessTokenTTL;
		this.accessTokenFormat = data.accessTokenFormat;
		this.jwt = data.jwt;
	}

	get scopes() {
		return new Set(this.scope?.split(' '));
	}

	identifier() {
		return this._identifier;
	}
}
