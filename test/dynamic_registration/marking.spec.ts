import { describe, beforeAll, it, expect } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { adapter } from 'lib/adapters/index.ts';
import { Client } from 'lib/models/client.ts';

/*
 * Telling a client the server created on its own request apart from one an administrator made.
 *
 * The marking is a stored field rather than a heuristic about the shape of an id, because the two
 * kinds are otherwise indistinguishable — a deployment's `idFactory` can issue any id it likes,
 * including a URL, which `test/client_id_uri/` already relies on.
 *
 * There is deliberately nothing here about per-project acceptance of registration. That was specified
 * and then removed: a registration request names no project, so the only way to build such a rule
 * would be a project-scoped registration endpoint, which hands an unauthenticated caller an oracle for
 * which projects exist. The project association arrives at authorization time instead, and
 * `test/cimd/project_association.spec.ts` covers it.
 */

const json = { 'content-type': 'application/json' };

/**
 * @proves A client the server created on a client request is marked as such, an operator client
 * never is, and a registrant cannot opt itself out.
 */
describe('marking a dynamically created registration', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'dynamic_registration' });
	});

	it('marks a client the server created on a client request', async () => {
		const res = await agent.reg.post(
			{ redirect_uris: ['https://client.example.com/cb'] },
			{ headers: json }
		);

		expect(res.status).toBe(201);
		const clientId = res.data?.client_id as string;

		const stored = (await adapter('Client').find(clientId)) as
			{ registeredDynamically?: boolean } | undefined;
		expect(stored?.registeredDynamically).toBe(true);
	});

	/*
	 * The seeded client stands for every administrator-created one: absence of the marking is what the
	 * console reads, so a stored `undefined` has to mean "an operator made this".
	 */
	it('leaves an administrator-created client unmarked', async () => {
		const stored = (await adapter('Client').find('client')) as
			{ registeredDynamically?: boolean } | undefined;

		expect(stored?.registeredDynamically).toBeUndefined();
	});

	/*
	 * A caller must not be able to disown the marking. It is applied after the wire translation, so a
	 * body claiming otherwise is simply overwritten rather than believed.
	 */
	it('ignores a registration body that claims not to be dynamic', async () => {
		const res = await agent.reg.post(
			{
				redirect_uris: ['https://client.example.com/cb'],
				registered_dynamically: false,
				registeredDynamically: false
			} as never,
			{ headers: json }
		);

		expect(res.status).toBe(201);
		const stored = (await adapter('Client').find(
			res.data?.client_id as string
		)) as { registeredDynamically?: boolean } | undefined;
		expect(stored?.registeredDynamically).toBe(true);
	});

	it('resolves such a client normally, marking and all', async () => {
		const res = await agent.reg.post(
			{ redirect_uris: ['https://client.example.com/cb'] },
			{ headers: json }
		);
		const clientId = res.data?.client_id as string;

		const client = await Client.tryFind(clientId);

		expect(client).toBeDefined();
		expect(client?.registeredDynamically).toBe(true);
	});

	it('stops honouring it once the registration is deleted', async () => {
		const res = await agent.reg.post(
			{ redirect_uris: ['https://client.example.com/cb'] },
			{ headers: json }
		);
		const clientId = res.data?.client_id as string;
		expect(await Client.tryFind(clientId)).toBeDefined();

		await adapter('Client').destroy(clientId);

		expect(await Client.tryFind(clientId)).toBeUndefined();
	});
});
