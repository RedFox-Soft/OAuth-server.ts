import { type Client } from '../models/client/types.ts';

import { InvalidClientMetadata } from './errors.ts';
import { sectorIdentifierUriValidate } from '../addon/index.js';
import { guardedFetch, readBounded } from '../shared/egress.js';

/*
 * A sector document is a JSON array of the client's own URIs. 64 KB holds well over a thousand of
 * them; nothing legitimate is larger, and a registrant must not be able to make this server hold an
 * arbitrary body in memory. Five seconds because this runs while a registration waits for an answer.
 */
const MAX_SECTOR_DOCUMENT_BYTES = 64 * 1024;
const SECTOR_FETCH_TIMEOUT_MS = 5_000;

function messageOf(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}

export default async function sectorValidate(client: Client) {
	const { sectorIdentifierUri } = client;
	// Called for a client that declares one; without it there is nothing to fetch.
	if (!sectorIdentifierUri || !sectorIdentifierUriValidate(client)) {
		return;
	}

	/*
	 * One refusal for every way the document could not be had — an address refused, a host that did
	 * not answer, a status other than 200 — because the address is the registrant's and the refusal is
	 * read by the registrant. Repeating what the target answered turned this into a port scanner for
	 * the network behind the server; the reason stays on this side.
	 */
	let text: string;
	try {
		const response = await guardedFetch(sectorIdentifierUri, {
			headers: { accept: 'application/json' },
			timeoutMs: SECTOR_FETCH_TIMEOUT_MS
		});
		if (response.status !== 200) throw new Error('status');
		text = await readBounded(response, MAX_SECTOR_DOCUMENT_BYTES);
	} catch {
		throw new InvalidClientMetadata(
			'sector_identifier_uri could not be retrieved'
		);
	}

	let body: unknown;
	try {
		body = JSON.parse(text);
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
