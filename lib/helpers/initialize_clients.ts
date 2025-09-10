import instance from './weak_cache.ts';
import { InvalidClientMetadata } from './errors.ts';
import { isPlainObject } from './_/object.js';

function addStatic(metadata) {
	const { staticClients } = instance(this);
	if (!isPlainObject(metadata) || !metadata.clientId) {
		throw new InvalidClientMetadata(
			'client_id is mandatory property for statically configured clients'
		);
	}

	if (staticClients.has(metadata.clientId)) {
		throw new InvalidClientMetadata(
			'client_id must be unique amongst statically configured clients'
		);
	}

	staticClients.set(metadata.clientId, structuredClone(metadata));
}

export default function initializeClients(clients = []) {
	clients.map(addStatic, this);
}
