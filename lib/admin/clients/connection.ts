import { openidConfiguration } from '../../actions/discovery.js';
import { accountPageUrl } from '../../account_page/client.js';
import { addressing, type RequestBucket } from '../../configs/issuer.js';

/* When an application first and last received a token (spec 107); null until it has. */
export interface LastUsed {
	firstUsedAt: number;
	lastUsedAt: number;
}

/*
 * What an application needs to be configured, stated once for the console and for an agent (spec 107). The endpoints
 * are read from the document the project actually serves, so a feature switched off, or an operator's override,
 * changes them here exactly as it changes them for a client reading discovery.
 */
export interface Connection {
	issuer: string | null;
	discoveryUrl: string | null;
	clientId: string;
	redirectUris: string[];
	postLogoutRedirectUris: string[];
	endpoints: Record<string, string>;
	signInPageUrl: string | null;
	lastUsed: LastUsed | null;
}

/* The members of a discovery document a client is configured with: its endpoints and where its keys are. */
function isEndpoint(member: string): boolean {
	return member.endsWith('_endpoint') || member === 'jwks_uri';
}

export async function connectionOf(
	application: {
		clientId: string;
		redirectUris: readonly string[];
		postLogoutRedirectUris?: readonly string[];
	},
	bucket: RequestBucket,
	lastUsed: LastUsed | null
): Promise<Connection> {
	const { issuer, discoveryUrl } = addressing(bucket);
	/*
	 * A project without an address of its own answers at no issuer yet, so nothing here may be given to a client:
	 * every value would change the day it gets one.
	 */
	const endpoints: Record<string, string> = {};
	if (issuer !== null) {
		const document = await openidConfiguration(bucket);
		for (const [member, value] of Object.entries(document)) {
			if (isEndpoint(member) && typeof value === 'string') {
				endpoints[member] = value;
			}
		}
	}
	return {
		issuer,
		discoveryUrl,
		clientId: application.clientId,
		redirectUris: [...application.redirectUris],
		postLogoutRedirectUris: [...(application.postLogoutRedirectUris ?? [])],
		endpoints,
		signInPageUrl: issuer === null ? null : accountPageUrl(bucket),
		lastUsed
	};
}
