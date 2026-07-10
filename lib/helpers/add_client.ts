import sectorValidate from './sector_validate.ts';
import { Client } from '../models/client.js';

export default async function add(provider, metadata, { store = false } = {}) {
	const client = Client.validateClient(metadata);

	if (client.sectorIdentifierUri !== undefined) {
		await sectorValidate(provider, client);
	}

	if (store) {
		await Client.adapter.upsert(client.clientId, client.metadata());
	}
	return client;
}
