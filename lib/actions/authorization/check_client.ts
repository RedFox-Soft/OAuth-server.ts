import presence from '../../helpers/validate_presence.ts';
import { InvalidClient } from '../../helpers/errors.ts';
import { Client } from 'lib/models/client.js';

/*
 * Checks client_id
 */
export default async function checkClient(ctx) {
	presence(ctx, 'client_id');

	const client = await Client.find(ctx.oidc.params.client_id);

	if (!client) {
		// there's no point in checking again in authorization error handler
		ctx.oidc.noclient = true;
		throw new InvalidClient('client is invalid', 'client not found');
	}

	ctx.oidc.entity('Client', client);
}
