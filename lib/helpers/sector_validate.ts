import { STATUS_CODES } from 'node:http';

import { type Client } from '../models/client/types.ts';

import { InvalidClientMetadata } from './errors.ts';
import { sectorIdentifierUriValidate } from '../addon/index.js';

function messageOf(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}

export default async function sectorValidate(client: Client) {
	const { sectorIdentifierUri } = client;
	// Called for a client that declares one; without it there is nothing to fetch.
	if (!sectorIdentifierUri || !sectorIdentifierUriValidate(client)) {
		return;
	}

	const response = await fetch(new URL(sectorIdentifierUri).href, {
		method: 'GET',
		headers: {
			accept: 'application/json'
		}
	}).catch((err) => {
		throw new InvalidClientMetadata(
			'could not load sector_identifier_uri response',
			messageOf(err)
		);
	});

	if (response.status !== 200) {
		throw new InvalidClientMetadata(
			`unexpected sector_identifier_uri response status code, expected 200 OK, got ${response.status} ${STATUS_CODES[response.status]}`
		);
	}

	let body;
	try {
		body = await response.json();
	} catch (err) {
		throw new InvalidClientMetadata(
			'failed to parse sector_identifier_uri JSON response',
			messageOf(err)
		);
	}

	try {
		if (!Array.isArray(body))
			throw new Error('sector_identifier_uri must return single JSON array');
		if (client.responseTypes.length) {
			const match = client.redirectUris.every((uri) => body.includes(uri));
			if (!match)
				throw new Error(
					'all registered redirectUris must be included in the sector_identifier_uri response'
				);
		}

		if (
			client.grantTypes.includes('urn:openid:params:grant-type:ciba') ||
			client.grantTypes.includes('urn:ietf:params:oauth:grant-type:device_code')
		) {
			if (!body.includes(client.jwksUri))
				throw new Error(
					"client's jwks_uri must be included in the sector_identifier_uri response"
				);
		}
	} catch (err) {
		throw new InvalidClientMetadata(messageOf(err));
	}
}
