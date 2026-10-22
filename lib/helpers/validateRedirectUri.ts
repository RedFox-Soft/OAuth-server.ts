import { LOOPBACKS } from 'lib/consts/client_attributes.js';
import { InvalidClientMetadata, type OIDCProviderError } from './errors.js';

// Registration refuses with invalid_client_metadata; the authorization endpoint with invalid_request.
interface Refusal {
	label?: string;
	ErrorClass?: new (description: string) => OIDCProviderError;
	/*
	 * An address no write has judged before — one a pushed request presents unregistered. Held to the rule a write
	 * holds an added address to (lib/models/client/register.ts): plain http on a loopback host only. Not applied to
	 * the schema's own pass, which re-validates every stored client on every resolution.
	 */
	newUri?: boolean;
}

export function validateRedirectUri(
	uris: string[],
	appType: string,
	{
		label = 'redirectUris',
		ErrorClass = InvalidClientMetadata,
		newUri = false
	}: Refusal = {}
) {
	for (const redirectUri of uris) {
		const parsed = URL.parse(redirectUri);
		if (!parsed) {
			throw new ErrorClass(`${label} must only contain valid uris`);
		}

		const { hostname, protocol, hash } = parsed;

		if (hash) {
			throw new ErrorClass(`${label} must not contain fragments`);
		}

		if (appType === 'web' && !['https:', 'http:'].includes(protocol)) {
			throw new ErrorClass(`${label} must only contain web uris`);
		}

		if (newUri && protocol === 'http:' && !LOOPBACKS.has(hostname)) {
			throw new ErrorClass(`${label} using http must use a loopback host`);
		}

		if (appType === 'native') {
			switch (protocol) {
				case 'http:': // Loopback Interface Redirection
					if (!LOOPBACKS.has(hostname)) {
						throw new ErrorClass(
							`${label} for native clients using http as a protocol can only use loopback addresses as hostnames`
						);
					}
					break;
				case 'https:': // Claimed HTTPS URI Redirection
					if (LOOPBACKS.has(hostname)) {
						throw new ErrorClass(
							`${label} for native clients using claimed HTTPS URIs must not be using ${hostname} as hostname`
						);
					}
					break;
				default: // Private-use URI Scheme Redirection
					if (!protocol.includes('.')) {
						throw new ErrorClass(
							`${label} for native clients using Custom URI scheme should use reverse domain name based scheme`
						);
					}
			}
		}
	}
}
