import mapKeys from '../../helpers/_/map_keys.ts';
import snakeCase from '../../helpers/_/snake_case.ts';
import { type Client, type ClientRecord, type WireClient } from './types.ts';
import { buildRecognizedMetadata } from './schema.ts';
import { canonicalToSnake, snakeToCanonical } from './wire.ts';

/*
 * The three shapes of a client and the one conversion between each pair. A registration body is wire
 * form; storage holds a record — base attributes under canonical names, recognised metadata under
 * wire names — which is also exactly what validation reads; a validated client is camelCase. Record
 * to client is validation itself.
 */

// camelCase → the stored record: recognised metadata goes back to its wire name.
export function toStored(client: Client): ClientRecord {
	const recognized = buildRecognizedMetadata();

	return mapKeys(client, (value, key) => {
		const snaked = snakeCase(key);
		if (!recognized.includes(snaked)) {
			return key;
		}

		return snaked;
	});
}

// The metadata echoed to a registering client (RFC 7591 §3.2.1, RFC 7592 §3): all snake_case.
export function toWire(client: Client): WireClient {
	return canonicalToSnake(toStored(client));
}

// A registration body → the record validation reads.
export function fromWire(body: WireClient): ClientRecord {
	return snakeToCanonical(body);
}
