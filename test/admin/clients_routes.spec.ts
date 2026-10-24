import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { clientRoutes } from 'lib/admin/clients/routes.ts';
import { auditRoutes } from 'lib/admin/audit/routes.ts';
import {
	CreateClientBody,
	UpdateClientBody
} from 'lib/admin/clients/schema.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adapter, getBucketStore } from 'lib/adapters/index.ts';
import type { UserBucket } from 'lib/adapters/types.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { sessionFor, personalGroupId } from '../admin_session.ts';
import { answered } from './answered.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_CLIENT_ID,
	ADMIN_SESSION_COOKIE,
	UNASSIGNED_GROUP_ID,
	DEFAULT_BUCKET_ID
} from 'lib/admin/consts.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';
import { elysia } from 'lib/index.ts';
import type { Connection } from 'lib/admin/clients/connection.ts';
import { present } from 'test/shape.js';

const app = new Elysia().use(resolveAdmin).use(clientRoutes).use(auditRoutes);
const client = treaty(app);

async function sessionCookieFor(kind: AdminKind) {
	const user = await createAdministrator(kind, `${kind}-${Math.random()}@x.io`);
	const s = await sessionFor(user);
	return { cookie: `${ADMIN_SESSION_COOKIE}=${s._id}`, userId: user._id };
}

async function makeBucket(
	ownerGroupId: string = UNASSIGNED_GROUP_ID
): Promise<UserBucket> {
	const id = nanoid()
		.toLowerCase()
		.replace(/[^a-z0-9]/g, '');
	return getBucketStore().create({
		name: `apps ${id}`,
		slug: `apps-${id}`,
		ownerGroupId
	});
}

/* A plain administrator and a bucket their own group owns. */
async function tenant() {
	const session = await sessionCookieFor('plain');
	const bucket = await makeBucket(await personalGroupId(session.userId));
	return { ...session, bucket };
}

function applications(bucket: Pick<UserBucket, '_id'>) {
	return client.admin.api.projects({ id: bucket._id }).clients;
}

async function createPublic(bucket: Pick<UserBucket, '_id'>, cookie: string) {
	const created = await applications(bucket).post(
		{
			clientName: 'SPA',
			grantTypes: ['authorization_code'],
			redirectUris: ['https://spa.example.com/cb'],
			tokenEndpointAuthMethod: 'none'
		},
		{ headers: { cookie } }
	);
	expect(created.status).toBe(201);
	return answered(created.data).clientId;
}

async function createConfidential(
	bucket: Pick<UserBucket, '_id'>,
	cookie: string
) {
	const created = await applications(bucket).post(
		{
			grantTypes: ['client_credentials'],
			tokenEndpointAuthMethod: 'client_secret_basic'
		},
		{ headers: { cookie } }
	);
	expect(created.status).toBe(201);
	return answered(created.data);
}

async function storedBucketOf(clientId: string): Promise<unknown> {
	return (await adapter('Client').find(clientId))?.bucketId;
}

/* What a refusal tells the caller: its status and its message, and nothing else to tell two apart. */
function refusalOf(res: { status: number; error: unknown }) {
	const value = (res.error as { value?: { message?: unknown } } | null)?.value;
	return { status: res.status, message: value?.message };
}

/* An application that registered itself at the bucket's address, as dynamic registration stores one. */
async function selfRegisteredIn(bucket: Pick<UserBucket, '_id'>) {
	const clientId = `dcr-${nanoid()}`;
	await adapter('Client').upsert(clientId, {
		clientId,
		bucketId: bucket._id,
		registeredDynamically: true,
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://self.example.com/cb'],
		token_endpoint_auth_method: 'none'
	});
	return clientId;
}

/**
 * @proves An administrator manages the applications of a bucket they hold — each one created there stays
 * there through every edit — sees a new secret exactly once, and cannot reach another bucket's
 * applications, the administrators' or the Default bucket as a tenant, or an application that registered
 * itself.
 */
describe("a bucket's applications", () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	describe('what an application needs to be configured', () => {
		it("names the project's issuer, discovery address and the endpoints that address serves", async () => {
			const { cookie } = await sessionCookieFor('super');
			const bucket = await makeBucket();
			const id = await createPublic(bucket, cookie);

			const read = await applications(bucket)({ clientId: id }).get({
				headers: { cookie }
			});
			const { connection } = answered(read.data) as unknown as {
				connection: Connection;
			};

			const served = (await (
				await elysia.handle(
					new Request(present(connection.discoveryUrl, 'discoveryUrl'))
				)
			).json()) as Record<string, unknown>;
			expect(connection.issuer).toBe(served.issuer as string);
			expect(connection.endpoints.authorization_endpoint).toBe(
				served.authorization_endpoint as string
			);
			expect(connection.endpoints.token_endpoint).toBe(
				served.token_endpoint as string
			);
			expect(connection.endpoints.jwks_uri).toBe(served.jwks_uri as string);
			expect(connection.clientId).toBe(id);
			expect(connection.redirectUris).toEqual(['https://spa.example.com/cb']);
			// The project's own account page: its real sign-in page, with no authorization run for this application.
			expect(connection.signInPageUrl).toBe(
				`${present(connection.issuer, 'issuer')}/account/apps`
			);
		});

		it('gives no issuer, endpoints or sign-in page for a project without an address of its own', async () => {
			const { cookie } = await sessionCookieFor('super');
			const bucket = await getBucketStore().create({
				name: `unaddressed ${nanoid()}`,
				ownerGroupId: UNASSIGNED_GROUP_ID
			});
			const id = await createPublic(bucket, cookie);

			const read = await applications(bucket)({ clientId: id }).get({
				headers: { cookie }
			});
			const { connection } = answered(read.data) as unknown as {
				connection: Connection;
			};
			expect(connection.issuer).toBeNull();
			expect(connection.discoveryUrl).toBeNull();
			expect(connection.endpoints).toEqual({});
			expect(connection.signInPageUrl).toBeNull();
		});
	});

	describe('whether an application holds a secret', () => {
		it('reports no secret for a public application', async () => {
			const { cookie } = await sessionCookieFor('super');
			const bucket = await makeBucket();
			const id = await createPublic(bucket, cookie);
			const read = await applications(bucket)({ clientId: id }).get({
				headers: { cookie }
			});
			expect(answered(read.data).hasSecret).toBe(false);
		});

		it('reports a secret for a confidential application', async () => {
			const { cookie } = await sessionCookieFor('super');
			const bucket = await makeBucket();
			const created = await createConfidential(bucket, cookie);
			const read = await applications(bucket)({
				clientId: created.clientId
			}).get({ headers: { cookie } });
			expect(answered(read.data).hasSecret).toBe(true);
		});

		it('returns the secret an edit gives an application, once', async () => {
			const { cookie } = await sessionCookieFor('super');
			const bucket = await makeBucket();
			const id = await createPublic(bucket, cookie);
			const patched = await applications(bucket)({ clientId: id }).patch(
				{ tokenEndpointAuthMethod: 'client_secret_basic' },
				{ headers: { cookie } }
			);
			expect(patched.status).toBe(200);
			const minted = (patched.data as unknown as { secret?: string }).secret;
			expect(minted).toBeString();
			expect(answered(patched.data).hasSecret).toBe(true);

			const read = await applications(bucket)({ clientId: id }).get({
				headers: { cookie }
			});
			expect(answered(read.data)).not.toHaveProperty('secret');
			expect(JSON.stringify(read.data)).not.toContain(String(minted));
		});

		it('returns no secret from an edit that leaves the secret as it was', async () => {
			const { cookie } = await sessionCookieFor('super');
			const bucket = await makeBucket();
			const created = await createConfidential(bucket, cookie);
			const patched = await applications(bucket)({
				clientId: created.clientId
			}).patch({ clientName: 'Renamed' }, { headers: { cookie } });
			expect(patched.status).toBe(200);
			expect(patched.data).not.toHaveProperty('secret');
		});
	});

	it('refuses an anonymous caller', async () => {
		const bucket = await makeBucket();
		const res = await applications(bucket).get();
		expect(res.status).toBe(401);
	});

	it('creates an application that belongs to the bucket it was created in, and lists it there', async () => {
		const { cookie } = await sessionCookieFor('super');
		const bucket = await makeBucket();
		const created = await applications(bucket).post(
			{
				clientName: 'SPA',
				grantTypes: ['authorization_code'],
				redirectUris: ['https://a.example.com/cb'],
				tokenEndpointAuthMethod: 'none'
			},
			{ headers: { cookie } }
		);
		expect(created.status).toBe(201);
		const body = answered(created.data);
		expect(body.secret).toBeUndefined(); // public client
		expect(body.projectId).toBe(bucket._id);
		expect(await storedBucketOf(body.clientId)).toBe(bucket._id);
		const list = await applications(bucket).get({ headers: { cookie } });
		expect(answered(list.data).map((c) => c.clientId)).toEqual([body.clientId]);
	});

	it('returns a confidential secret once on create, never on GET', async () => {
		const { cookie } = await sessionCookieFor('super');
		const bucket = await makeBucket();
		const body = await createConfidential(bucket, cookie);
		expect(body.secret).toBeTruthy();
		const one = await applications(bucket)({ clientId: body.clientId }).get({
			headers: { cookie }
		});
		const view = answered(one.data);
		expect(view).not.toHaveProperty('secret');
		expect(view).not.toHaveProperty('clientSecret');
		// The connection values are what a developer reads back later; the secret is never among them.
		expect(view).toHaveProperty('connection');
		expect(JSON.stringify(view)).not.toContain(String(body.secret));
	});

	/*
	 * CIMD §7.2: an administrator may pre-register a Client Identifier URL. Under the IPSIE SL1 profile it is the only
	 * way such a client exists, since the profile never fetches a document.
	 */
	describe('an application created under a Client Identifier URL', () => {
		const url = () =>
			`https://app-${nanoid()
				.toLowerCase()
				.replace(/[^a-z0-9]/g, '')}.example.com/oauth/client.json`;

		it('is created with that URL as its client id', async () => {
			const { cookie } = await sessionCookieFor('super');
			const identifier = url();

			const created = await applications(await makeBucket()).post(
				{
					clientIdentifierUrl: identifier,
					clientName: 'Pre-registered',
					grantTypes: ['authorization_code'],
					redirectUris: ['https://pre.example.com/cb'],
					tokenEndpointAuthMethod: 'none'
				},
				{ headers: { cookie } }
			);

			expect(created.status).toBe(201);
			expect(answered(created.data).clientId).toBe(identifier);
		});

		it('is refused when the URL is not a Client Identifier URL', async () => {
			const { cookie } = await sessionCookieFor('super');

			const refused = await applications(await makeBucket()).post(
				{
					clientIdentifierUrl: 'http://app.example.com/oauth/client.json',
					clientName: 'Plain http',
					grantTypes: ['authorization_code'],
					redirectUris: ['https://pre.example.com/cb'],
					tokenEndpointAuthMethod: 'none'
				},
				{ headers: { cookie } }
			);

			expect(refused.status).toBe(422);
			expect(JSON.stringify(refused.error?.value)).toContain(
				'clientIdentifierUrl'
			);
		});

		it('is refused when an application already has that URL as its client id', async () => {
			const { cookie } = await sessionCookieFor('super');
			const identifier = url();
			const body = {
				clientIdentifierUrl: identifier,
				clientName: 'Pre-registered',
				grantTypes: ['authorization_code' as const],
				redirectUris: ['https://pre.example.com/cb'],
				tokenEndpointAuthMethod: 'none' as const
			};
			expect(
				(
					await applications(await makeBucket()).post(body, {
						headers: { cookie }
					})
				).status
			).toBe(201);

			const refused = await applications(await makeBucket()).post(body, {
				headers: { cookie }
			});

			expect(refused.status).toBe(409);
		});
	});

	it('maps invalid client metadata to 422', async () => {
		const { cookie } = await sessionCookieFor('super');
		const bucket = await makeBucket();
		// authorization_code with no redirect_uris is invalid
		const res = await applications(bucket).post(
			{ grantTypes: ['authorization_code'], tokenEndpointAuthMethod: 'none' },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(422);
	});

	/*
	 * The editor used to offer a CIBA delivery mode of 'push'. Nothing implements it — the flow handles
	 * 'poll' and 'ping' only — and configuration validation refuses any mode outside those two, so an
	 * operator who picked it got their client rejected with no explanation of why an offered choice was
	 * not a choice.
	 *
	 * Asserted against the request schema itself rather than over HTTP, deliberately: a POST carrying
	 * 'push' is refused either way (client-metadata validation derives its allowed values from
	 * ciba.deliveryModes, which never contains 'push'), so an HTTP assertion would pass before and
	 * after and prove nothing. What changed is which set the operator is *offered*, and that set is
	 * this schema — the same list the console's Select mirrors.
	 */
	it('offers only the delivery modes the server implements', () => {
		const offered = (
			schema: typeof CreateClientBody | typeof UpdateClientBody
		) =>
			schema.properties.backchannelTokenDeliveryMode.anyOf.map(
				(member) => member.const
			);

		expect(offered(CreateClientBody)).toEqual(['poll', 'ping']);
		expect(offered(UpdateClientBody)).toEqual(['poll', 'ping']);
	});

	it('still accepts the two delivery modes the server does implement', async () => {
		const { cookie } = await sessionCookieFor('super');
		const bucket = await makeBucket();
		ApplicationConfig['ciba.enabled'] = true;
		ApplicationConfig['ciba.deliveryModes'] = ['poll', 'ping'];
		try {
			for (const mode of ['poll', 'ping'] as const) {
				const res = await applications(bucket).post(
					{
						grantTypes: ['urn:openid:params:grant-type:ciba'],
						tokenEndpointAuthMethod: 'client_secret_basic',
						backchannelTokenDeliveryMode: mode,
						...(mode === 'ping'
							? {
									backchannelClientNotificationEndpoint:
										'https://rp.example.com/ciba'
								}
							: undefined)
					},
					{ headers: { cookie } }
				);
				expect(res.status).not.toBe(422);
			}
		} finally {
			ApplicationConfig['ciba.enabled'] = false;
			ApplicationConfig['ciba.deliveryModes'] = ['poll'];
		}
	});

	it('refuses to create an application that would get machine tokens without authenticating', async () => {
		const { cookie } = await sessionCookieFor('super');
		const bucket = await makeBucket();
		const res = await applications(bucket).post(
			{ grantTypes: ['client_credentials'], tokenEndpointAuthMethod: 'none' },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(422);
	});

	it('refuses to give client_credentials to an application that does not authenticate', async () => {
		const { cookie } = await sessionCookieFor('super');
		const bucket = await makeBucket();
		const id = await createPublic(bucket, cookie);
		const patched = await applications(bucket)({ clientId: id }).patch(
			{ grantTypes: ['authorization_code', 'client_credentials'] },
			{ headers: { cookie } }
		);
		expect(patched.status).toBe(422);
		const reloaded = await applications(bucket)({ clientId: id }).get({
			headers: { cookie }
		});
		expect(answered(reloaded.data).grantTypes).toEqual(['authorization_code']);
	});

	it('updates an application via PATCH', async () => {
		const { cookie } = await sessionCookieFor('super');
		const bucket = await makeBucket();
		const id = await createPublic(bucket, cookie);
		const patched = await applications(bucket)({ clientId: id }).patch(
			{ redirectUris: ['https://updated.example.com/cb'] },
			{ headers: { cookie } }
		);
		expect(patched.status).toBe(200);
		const reloaded = await applications(bucket)({ clientId: id }).get({
			headers: { cookie }
		});
		expect(answered(reloaded.data).redirectUris).toEqual([
			'https://updated.example.com/cb'
		]);
	});

	it('rotates the secret of a confidential application', async () => {
		const { cookie } = await sessionCookieFor('super');
		const bucket = await makeBucket();
		const { clientId, secret } = await createConfidential(bucket, cookie);
		const rotated = await applications(bucket)({ clientId }).secret.post(
			undefined,
			{ headers: { cookie } }
		);
		expect(rotated.status).toBe(200);
		const fresh = answered(rotated.data).secret;
		expect(fresh).toBeTruthy();
		expect(fresh).not.toBe(secret);
	});

	it('refuses with 400 to rotate the secret of a public application', async () => {
		const { cookie } = await sessionCookieFor('super');
		const bucket = await makeBucket();
		const id = await createPublic(bucket, cookie);
		const res = await applications(bucket)({ clientId: id }).secret.post(
			undefined,
			{ headers: { cookie } }
		);
		expect(res.status).toBe(400);
	});

	it('deletes an application, which then answers not found and is no longer listed', async () => {
		const { cookie } = await sessionCookieFor('super');
		const bucket = await makeBucket();
		const id = await createPublic(bucket, cookie);
		const del = await applications(bucket)({ clientId: id }).delete(undefined, {
			headers: { cookie }
		});
		expect(del.status).toBe(200);
		const after = await applications(bucket)({ clientId: id }).get({
			headers: { cookie }
		});
		expect(after.status).toBe(404);
		const list = await applications(bucket).get({ headers: { cookie } });
		expect(answered(list.data)).toEqual([]);
	});

	it("refuses a super administrator managing the console's own client through the administrators' bucket", async () => {
		const { cookie } = await sessionCookieFor('super');
		const res = await applications({ _id: ADMIN_BUCKET_ID })({
			clientId: ADMIN_CLIENT_ID
		}).delete(undefined, { headers: { cookie } });
		expect(refusalOf(res)).toEqual({
			status: 403,
			message: "this operation is not available for the administrators' project"
		});
		expect(await adapter('Client').find(ADMIN_CLIENT_ID)).toBeTruthy();
	});

	it('answers an application of another bucket as a missing one, for a super administrator too', async () => {
		const { cookie } = await sessionCookieFor('super');
		const home = await makeBucket();
		const elsewhere = await makeBucket();
		const clientId = await createPublic(home, cookie);
		const cross = await applications(elsewhere)({ clientId }).get({
			headers: { cookie }
		});
		const missing = await applications(elsewhere)({
			clientId: `absent-${nanoid()}`
		}).get({ headers: { cookie } });
		expect(refusalOf(cross)).toEqual({
			status: 404,
			message: 'client not found'
		});
		expect(refusalOf(cross)).toEqual(refusalOf(missing));
	});

	describe('by a tenant', () => {
		it('creates, reads, updates, rotates and deletes an application in a bucket their group owns', async () => {
			const { cookie, bucket } = await tenant();

			const created = answered(
				(
					await applications(bucket).post(
						{
							clientName: 'Backend',
							grantTypes: ['client_credentials'],
							tokenEndpointAuthMethod: 'client_secret_basic'
						},
						{ headers: { cookie } }
					)
				).data
			);
			expect(created.projectId).toBe(bucket._id);
			const app = applications(bucket)({ clientId: created.clientId });

			const read = await app.get({ headers: { cookie } });
			expect(answered(read.data).clientName).toBe('Backend');
			const renamed = await app.patch(
				{ clientName: 'Billing backend' },
				{ headers: { cookie } }
			);
			expect(answered(renamed.data).clientName).toBe('Billing backend');
			const rotated = await app.secret.post(undefined, { headers: { cookie } });
			expect(answered(rotated.data).secret).toBeTruthy();
			const deleted = await app.delete(undefined, { headers: { cookie } });
			expect(deleted.status).toBe(200);
			expect((await app.get({ headers: { cookie } })).status).toBe(404);
		});

		it("finds the creation of their application in their own group's audit trail", async () => {
			const { cookie, bucket, userId } = await tenant();
			const clientId = await createPublic(bucket, cookie);

			const trail = await client.admin.api.audit.get({
				query: { targetId: clientId },
				headers: { cookie }
			});

			expect(trail.status).toBe(200);
			const { entries } = answered(trail.data);
			expect(entries).toHaveLength(1);
			expect(entries[0]).toMatchObject({
				action: 'client.create',
				targetId: clientId,
				projectId: bucket._id,
				ownerTeamId: await personalGroupId(userId)
			});
		});

		it.each(['GET', 'PATCH', 'DELETE'] as const)(
			"answers %s of another bucket's application exactly as a missing one, and leaves it as it was",
			async (method) => {
				const su = await sessionCookieFor('super');
				const { cookie, bucket } = await tenant();
				const theirs = await createPublic(await makeBucket(), su.cookie);
				const before = await adapter('Client').find(theirs);
				expect(before).toBeTruthy();

				const call = (clientId: string) => {
					const app = applications(bucket)({ clientId });
					const headers = { headers: { cookie } };
					return method === 'GET'
						? app.get(headers)
						: method === 'PATCH'
							? app.patch({ clientName: 'taken' }, headers)
							: app.delete(undefined, headers);
				};
				const cross = await call(theirs);
				const missing = await call(`absent-${nanoid()}`);

				expect(refusalOf(cross)).toEqual({
					status: 404,
					message: 'client not found'
				});
				expect(refusalOf(cross)).toEqual(refusalOf(missing));
				expect(await adapter('Client').find(theirs)).toEqual(before);
			}
		);

		it('answers a bucket of another group exactly as a bucket that does not exist', async () => {
			const { cookie } = await tenant();
			const theirs = await makeBucket();

			const unreachable = await applications(theirs).get({
				headers: { cookie }
			});
			const missing = await applications({ _id: `absent-${nanoid()}` }).get({
				headers: { cookie }
			});

			expect(refusalOf(unreachable)).toEqual({
				status: 403,
				message: 'no access to this project'
			});
			expect(refusalOf(unreachable)).toEqual(refusalOf(missing));
		});

		it.each([
			['the administrators’', ADMIN_BUCKET_ID],
			['the Default', DEFAULT_BUCKET_ID]
		])(
			'is refused creating an application in %s bucket, and nothing is stored there',
			async (_, bucketId) => {
				const { cookie } = await tenant();
				const before = await adapter('Client').findByIndexed(
					'bucketId',
					bucketId
				);

				const res = await applications({ _id: bucketId }).post(
					{
						grantTypes: ['authorization_code'],
						redirectUris: ['https://squat.example.com/cb'],
						tokenEndpointAuthMethod: 'none'
					},
					{ headers: { cookie } }
				);

				expect(res.status).toBe(403);
				expect(
					await adapter('Client').findByIndexed('bucketId', bucketId)
				).toHaveLength(before.length);
			}
		);
	});

	describe('keeps an application in its bucket', () => {
		it('through an edit that names another bucket', async () => {
			const { cookie, bucket } = await tenant();
			const other = await makeBucket();
			const clientId = await createPublic(bucket, cookie);

			const res = await applications(bucket)({ clientId }).patch(
				// @ts-expect-error submitted as unknown fields, the edge name and the stored one; the schema accepts neither.
				{ clientName: 'moved?', projectId: other._id, bucketId: other._id },
				{ headers: { cookie } }
			);

			expect([200, 422]).toContain(res.status);
			expect(await storedBucketOf(clientId)).toBe(bucket._id);
		});

		it('through an edit of its other attributes', async () => {
			const { cookie, bucket } = await tenant();
			const clientId = await createPublic(bucket, cookie);

			const res = await applications(bucket)({ clientId }).patch(
				{
					redirectUris: ['https://after.example.com/cb'],
					requireConsent: false
				},
				{ headers: { cookie } }
			);

			expect(res.status).toBe(200);
			expect(answered(res.data).projectId).toBe(bucket._id);
			expect(await storedBucketOf(clientId)).toBe(bucket._id);
		});

		it('through a secret rotation', async () => {
			const { cookie, bucket } = await tenant();
			const { clientId } = await createConfidential(bucket, cookie);

			const res = await applications(bucket)({ clientId }).secret.post(
				undefined,
				{ headers: { cookie } }
			);

			expect(res.status).toBe(200);
			expect(await storedBucketOf(clientId)).toBe(bucket._id);
		});
	});

	describe('that registered itself', () => {
		it('lists it with the applications an administrator created', async () => {
			const { cookie, bucket } = await tenant();
			const created = await createPublic(bucket, cookie);
			const registered = await selfRegisteredIn(bucket);

			const list = await applications(bucket).get({ headers: { cookie } });

			const listed = answered(list.data);
			expect(listed.map((c) => c.clientId).sort()).toEqual(
				[created, registered].sort()
			);
			expect(
				listed.find((c) => c.clientId === registered)?.registeredDynamically
			).toBe(true);
		});

		it.each(['PATCH', 'secret rotation', 'DELETE'] as const)(
			'refuses %s with 409 and leaves it as it was',
			async (change) => {
				const { cookie, bucket } = await tenant();
				const clientId = await selfRegisteredIn(bucket);
				const before = await adapter('Client').find(clientId);

				const app = applications(bucket)({ clientId });
				const headers = { headers: { cookie } };
				const res =
					change === 'PATCH'
						? await app.patch({ requireConsent: false }, headers)
						: change === 'DELETE'
							? await app.delete(undefined, headers)
							: await app.secret.post(undefined, headers);

				expect(res.status).toBe(409);
				expect(await adapter('Client').find(clientId)).toEqual(before);
			}
		);
	});
});
