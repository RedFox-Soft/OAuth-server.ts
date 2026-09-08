import { describe, beforeAll, it, expect } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { ApplicationConfig } from 'lib/configs/application.ts';

/*
 * That the advertised capability follows the actual one.
 *
 * A client is told to check for this member before presenting a URL-shaped `client_id`, and to fall
 * back to another mechanism otherwise. So advertising it while the server would refuse the mechanism
 * is worse than not advertising it at all: it converts a working fallback into a guaranteed failure.
 */

async function member() {
	const res = await agent['.well-known']['oauth-authorization-server'].get();
	return (res.data as Record<string, unknown> | undefined)?.[
		'client_id_metadata_document_supported'
	];
}

describe('client_id_metadata_document_supported', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'cimd' });
	});

	it('is advertised while the capability is on', async () => {
		expect(await member()).toBe(true);
	});

	it('is absent while the capability is off', async () => {
		ApplicationConfig['clientIdMetadataDocument.enabled'] = false;
		try {
			expect(await member()).toBeUndefined();
		} finally {
			ApplicationConfig['clientIdMetadataDocument.enabled'] = true;
		}
	});
});
