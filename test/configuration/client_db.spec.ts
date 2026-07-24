import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap, { seedClient } from '../test_helper.js';
import { adapter } from '../../lib/adapters/index.ts';
import { Client } from 'lib/models/client.js';

// Clients are single-sourced from adapter('Client'). These specs pin the
// resolution contract: seeded clients resolve, updates/deletes are reflected
// immediately (no stale window), unknown clients raise invalid_client, and one
// module never inherits another module's seeded clients.
describe('clients resolved from the storage adapter', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'client_db' });
	});

	it('resolves a client seeded into the adapter', async () => {
		const client = await Client.find('db-client');
		expect(client.clientId).toBe('db-client');
	});

	it('reflects an update in the store immediately (no stale window)', async () => {
		// Populate the validation memo first, then mutate the stored record.
		await Client.find('db-client');
		const current = await adapter('Client').find('db-client');
		await adapter('Client').upsert('db-client', {
			...current,
			redirectUris: ['https://client.example.com/updated']
		});

		const updated = await Client.find('db-client');
		expect(updated.redirectUris).toEqual([
			'https://client.example.com/updated'
		]);
	});

	it('raises invalid_client for an unknown client_id', async () => {
		await expect(Client.find('no-such-client')).rejects.toThrow();
	});

	it('stops resolving a client once it is deleted from the store', async () => {
		seedClient({
			clientId: 'ephemeral-client',
			clientSecret: 'secret',
			grantTypes: ['authorization_code'],
			responseTypes: ['code'],
			redirectUris: ['https://client.example.com/cb']
		});
		expect((await Client.find('ephemeral-client')).clientId).toBe(
			'ephemeral-client'
		);

		await adapter('Client').destroy('ephemeral-client');
		expect(await Client.tryFind('ephemeral-client')).toBeUndefined();
	});

	it('does not inherit clients seeded by other test modules (isolation)', async () => {
		// `client` is the ubiquitous id used across most other suites; the
		// per-module TestAdapter.clear() in bootstrap must keep it out of here.
		expect(await Client.tryFind('client')).toBeUndefined();
	});
});
