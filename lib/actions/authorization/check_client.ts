import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
import presence from '../../helpers/validate_presence.ts';
import { InvalidClient } from '../../helpers/errors.ts';
import { Client } from 'lib/models/client.js';

/*
 * Checks client_id
 */
export default async function checkClient(oidc: OIDCContext<PipelineParams>) {
	presence(oidc, 'client_id');
	const client = await Client.find(oidc.params.client_id, {
		error: new InvalidClient('client is invalid', 'client not found')
	});
	oidc.entity('Client', client);
}
