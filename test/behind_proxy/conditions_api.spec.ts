import {
	afterAll,
	beforeAll,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';

import bootstrap, { seedClient } from '../test_helper.js';
import { getBucketGroupStore, getUserStore } from 'lib/adapters/index.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { admin } from '../provisioning/helpers.ts';
import { group, member, world, type Member, type World } from './helpers.ts';
import {
	apiCheck,
	bearer,
	declareApi,
	jwtFor,
	opaqueFor,
	resourcesPath,
	type ApiView
} from './api_helpers.ts';

let w: World;
let ops: string;
let opsMember: Member;
let api: ApiView;
let humanClient: string;
let machineClient: string;
let pairwiseClient: string;

function seconds(): number {
	return Math.floor(Date.now() / 1000);
}

/* A token a person got through an interactive sign-in, at this API, for `client`. */
function personToken(
	who: Member,
	client: string,
	claims: Record<string, unknown> = {}
) {
	return jwtFor(api, {
		claims: {
			sub: who.accountId,
			client_id: client,
			auth_time: seconds(),
			...claims
		}
	});
}

function call(token: string): Promise<Response> {
	return apiCheck({
		slug: w.acme.slug,
		identifier: api.identifier,
		authorization: bearer(token),
		mcpMethod: 'tools/list'
	});
}

/**
 * @proves An API checked at the proxy can be limited to some groups of the project, and only a token that truly stands
 * for a person who may still sign in passes: a machine's token, a token whose person cannot be traced, and a token of
 * a person since locked or moved out of the group do not.
 */
describe('who can call an API checked at the proxy', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
		opsMember = await member(w.acme);
		ops = await group(w.acme.id, 'Ops', [opsMember.accountId]);
		humanClient = `human-${nanoid()}`;
		machineClient = `machine-${nanoid()}`;
		pairwiseClient = `pairwise-${nanoid()}`;
		for (const [clientId, grantTypes, subjectType] of [
			[humanClient, ['authorization_code'], 'public'],
			[machineClient, ['client_credentials'], 'public'],
			[pairwiseClient, ['authorization_code'], 'pairwise']
		] as const) {
			seedClient({
				clientId,
				bucketId: w.acme.id,
				clientName: clientId,
				applicationType: 'web',
				redirectUris: ['https://rp.example.com/cb'],
				responseTypes: grantTypes[0] === 'authorization_code' ? ['code'] : [],
				grantTypes: [...grantTypes],
				subjectType,
				token_endpoint_auth_method: 'none'
			});
		}
		api = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });
		const reply = await admin(
			'PATCH',
			resourcesPath(w.acme.id, api.identifier),
			w.cookie,
			{
				tools: {
					rows: [],
					otherTools: 'refuse',
					withoutMethod: 'refuse',
					access: { conditions: [{ kind: 'group', groups: [ops] }] }
				}
			}
		);
		expect(reply.status).toBe(200);
	});

	afterAll(() => {
		setSystemTime();
	});

	describe('a token that stands for no person this check can name', () => {
		it.each([
			['a machine token', async () => (await opaqueFor(api, w.acme.id)).value],
			[
				'a self-contained token with no sign-in time',
				() => personToken(opsMember, humanClient, { auth_time: undefined })
			],
			[
				'a pairwise client’s token',
				() => personToken(opsMember, pairwiseClient)
			],
			[
				'a token whose subject is its client',
				() =>
					jwtFor(api, {
						claims: {
							sub: humanClient,
							client_id: humanClient,
							auth_time: seconds()
						}
					})
			]
		] as const)('%s is refused as no person', async (_case, mint) => {
			const response = await call(await mint());

			expect(response.status).toBe(403);
			expect(response.headers.get('x-auth-reason')).toBe('no_person');
		});
	});

	describe('members of Ops', () => {
		it('a person in Ops is let through, one outside is refused, and one removed is refused once a minute has passed', async () => {
			const outsider = await member(w.acme);
			const leaving = await member(w.acme);
			await getBucketGroupStore().change(ops, {
				add: [leaving.accountId],
				remove: []
			});

			const inOps = await call(await personToken(opsMember, humanClient));
			const notInOps = await call(await personToken(outsider, humanClient));
			const beforeLeaving = await call(await personToken(leaving, humanClient));
			await getBucketGroupStore().change(ops, {
				add: [],
				remove: [leaving.accountId]
			});
			setSystemTime(Date.now() + 61_000);
			const afterLeaving = await call(await personToken(leaving, humanClient));
			setSystemTime();

			expect(inOps.status).toBe(200);
			expect(notInOps.headers.get('x-auth-reason')).toBe('not_in_group');
			expect(beforeLeaving.status).toBe(200);
			expect(afterLeaving.headers.get('x-auth-reason')).toBe('not_in_group');
		});

		it('a person deactivated after their token was issued is refused at once', async () => {
			const soon = await member(w.acme);
			await getBucketGroupStore().change(ops, {
				add: [soon.accountId],
				remove: []
			});
			const token = await personToken(soon, humanClient);
			const before = await call(token);

			await getUserStore(w.acme.id).update(soon.accountId, { active: false });
			const after = await call(token);

			expect(before.status).toBe(200);
			expect(after.status).toBe(403);
			expect(after.headers.get('x-auth-reason')).toBe('cannot_sign_in');
		});
	});

	describe('saving a condition about the person', () => {
		it('names the applications that receive tokens for no person and those with pairwise subjects', async () => {
			const reply = await admin(
				'PATCH',
				resourcesPath(w.acme.id, api.identifier),
				w.cookie,
				{
					tools: {
						rows: [],
						otherTools: 'refuse',
						withoutMethod: 'refuse',
						access: { conditions: [{ kind: 'group', groups: [ops] }] }
					}
				}
			);

			expect(reply.status).toBe(200);
			const { warnings } = reply.body as {
				warnings: { machineClients: string[]; pairwiseClients: string[] };
			};
			expect(warnings.machineClients).toContain(machineClient);
			expect(warnings.pairwiseClients).toContain(pairwiseClient);
		});

		it('is refused on an API whose own server checks its tokens', async () => {
			const own = await declareApi(w.cookie, w.acme.id);

			const reply = await admin(
				'PATCH',
				resourcesPath(w.acme.id, own.identifier),
				w.cookie,
				{
					tools: {
						rows: [],
						otherTools: 'refuse',
						withoutMethod: 'refuse',
						access: { conditions: [{ kind: 'group', groups: [ops] }] }
					}
				}
			);

			expect(reply.status).toBe(422);
		});
	});
});
