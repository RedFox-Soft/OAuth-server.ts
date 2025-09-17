import { LOOPBACKS } from 'lib/consts/client_attributes.js';
import { InvalidClientMetadata } from './errors.js';

export function validateRedirectUri(
	uris: string[],
	appType: string,
	{ label = 'redirectUris', ErrorClass = InvalidClientMetadata } = {}
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
