import { InvalidClientMetadata } from './errors.ts';
import { type SectorSource } from '../models/client/sector.ts';

export default (client: SectorSource): string | undefined => {
	if (client.subjectType === 'pairwise') {
		if (!client.sectorIdentifierUri) {
			switch (true) {
				case client.responseTypes.length !== 0:
					return new URL(client.redirectUris[0]).host;
				case client.grantTypes.includes('urn:openid:params:grant-type:ciba'):
				case client.grantTypes.includes(
					'urn:ietf:params:oauth:grant-type:device_code'
				):
					// Asserted: validation requires jwks_uri of a pairwise client on these grants.
					return new URL(client.jwksUri as string).host;
				default:
					throw new InvalidClientMetadata(
						'could not determine a sector identifier'
					);
			}
		}
	}

	return client.sectorIdentifierUri
		? new URL(client.sectorIdentifierUri).host
		: undefined;
};
