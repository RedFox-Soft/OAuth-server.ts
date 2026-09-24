/*
 * What getResourceServerInfo answers for a resource indicator: the scopes it offers and, optionally, the
 * audience its tokens carry and how they look (opaque unless it says otherwise).
 */
export type ResourceServerInfo = {
	scope: string;
	audience?: string;
	accessTokenFormat?: 'jwt' | 'opaque';
	accessTokenTTL?: number;
	jwt?: Record<string, unknown>;
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
