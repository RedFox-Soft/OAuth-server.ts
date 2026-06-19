import sectorValidate from './sector_validate.ts';

export default async function add(provider, metadata, { store = false } = {}) {
	const client = provider.Client.validateClient(metadata);

	if (client.sectorIdentifierUri !== undefined) {
		await sectorValidate(provider, client);
	}

	if (store) {
		await provider.Client.adapter.upsert(client.clientId, client.metadata());
	}
	return client;
}
