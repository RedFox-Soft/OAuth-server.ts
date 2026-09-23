import { AccessToken } from 'lib/models/access_token.js';
import { ClientCredentials } from 'lib/models/client_credentials.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { hasGrant } from '../actions/grants/index.js';
import type { OIDCContext } from '../helpers/oidc_context.js';

const uriMapTypes: Record<string, string> = {
	'urn:ietf:params:oauth:token-type:access_token': 'access_token',
	'urn:ietf:params:oauth:token-type:refresh_token': 'refresh_token'
};

const tokenTypes = {
	access_token(token: string) {
		return AccessToken.tryFind(token);
	},
	async client_credentials(token: string) {
		if (!hasGrant('client_credentials')) {
			return;
		}
		return ClientCredentials.tryFind(token);
	},
	refresh_token(token: string) {
		return RefreshToken.tryFind(token);
	}
};
type TokenType = keyof typeof tokenTypes;

function isTokenType(type?: string): type is TokenType {
	if (type === undefined) {
		return false;
	}
	const tType = type in uriMapTypes ? uriMapTypes[type] : type;
	return tType in tokenTypes;
}
type Token = AccessToken | RefreshToken | ClientCredentials;

export async function findToken(
	id: string,
	hint?: string
): Promise<Token | undefined> {
	let token: Token | undefined;

	if (isTokenType(hint)) {
		const methodToken = tokenTypes[hint];
		token = await methodToken(id);
		if (!token) {
			const otherMethods = (Object.keys(tokenTypes) as TokenType[])
				.filter((type) => type !== hint)
				.map((type) => tokenTypes[type](id));
			token = (await Promise.all(otherMethods)).find((t) => t);
		}
	} else {
		token = (
			await Promise.all(Object.values(tokenTypes).map((fn) => fn(id)))
		).find((t) => t);
	}
	return token;
}

/*
 * Stores a found token on the request under the name of its own kind. Narrowed by class rather than by
 * `payload.kind`, which the schema declares as any string: a token class added to `Token` without a
 * branch here fails to compile instead of being stored under a name nothing reads.
 */
export function storeToken(oidc: OIDCContext, token: Token) {
	if (token instanceof AccessToken) {
		oidc.entity('AccessToken', token);
	} else if (token instanceof RefreshToken) {
		oidc.entity('RefreshToken', token);
	} else {
		oidc.entity('ClientCredentials', token);
	}
}
