import presence from '../../helpers/validate_presence.ts';
import { InvalidClient } from '../../helpers/errors.ts';
import { Client } from 'lib/models/client.js';

/*
 * Checks client_id
 */
export default async function checkClient(oidc) {
	presence(oidc, 'client_id');

	const client = await Client.find(oidc.params.client_id);

	if (!client) {
		// there's no point in checking again in authorization error handler
		oidc.noclient = true;
		throw new InvalidClient('client is invalid', 'client not found');
	}

	oidc.entity('Client', client);
}
