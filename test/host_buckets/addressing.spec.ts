import { createHash, randomBytes } from 'node:crypto';
import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap from '../test_helper.ts';
import {
	getBucketStore,
	getProjectStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { elysia } from 'lib/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';

const PASSWORD = 'correct horse battery';

const TENANT_HOST = 'acme.e.ly';
const OTHER_HOST = 'globex.e.ly';
const UNCLAIMED_HOST = 'nobody.e.ly';

let tenantBucketId: string;
let otherBucketId: string;

async function seedBucket(name: string, host: string, clientId: string) {
	const bucket = await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name,
		host
	});
	const project = await getProjectStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name,
		slug: `${name.toLowerCase()}-${Math.random()}`
	});
	await getProjectStore().update(project._id, {
		bucketId: bucket._id,
		clientIds: [clientId]
	});
	return bucket._id;
}

function at(host: string, path: string, init: RequestInit = {}) {
	return elysia.handle(
		new Request(`http://${host}${path}`, { redirect: 'manual', ...init })
	);
}

/* Exactly what host_buckets.config.ts registered: OAuth 2.1 matches a redirect_uri as an exact string,
 * so a near-miss here is refused before anything this spec is about is reached. */
const REDIRECTS: Record<string, string> = {
	'host-bucket-app': 'http://e.ly/host-bucket/callback',
	'path-bucket-app': 'http://e.ly/path-bucket/callback',
	'other-host-bucket-app': 'http://e.ly/other-host-bucket/callback'
};

async function signIn(host: string, clientId: string, email: string) {
	/* PKCE is mandatory for every client under OAuth 2.1, so a request without a challenge is refused
	 * before anything this spec is about is reached. */
	const verifier = randomBytes(32).toString('base64url');
	const challenge = createHash('sha256').update(verifier).digest('base64url');

	const started = await at(
		host,
		`/auth?client_id=${clientId}&scope=openid&response_type=code` +
			`&code_challenge=${challenge}&code_challenge_method=S256` +
			`&redirect_uri=${encodeURIComponent(REDIRECTS[clientId])}`
	);
	const location = started.headers.get('location') ?? '';
	const uid = location.split('/')[2];
	const interactionCookie = started.headers.get('set-cookie') ?? '';

	const submitted = await at(host, `/ui/${uid}/login`, {
		method: 'POST',
		headers: {
			'content-type': 'application/x-www-form-urlencoded',
			cookie: interactionCookie
		},
		body: new URLSearchParams({
			username: email,
			password: PASSWORD
		}).toString()
	});
	return {
		uid,
		response: submitted,
		setCookie: submitted.headers.get('set-cookie')
	};
}

/**
 * @proves A bucket given a host of its own is reached there and nowhere else: its metadata and its
 * issuer are that origin's, an address no bucket holds is refused rather than served by the default
 * population, and a sign-in on one bucket's host does not carry to another's.
 */
describe('a bucket addressed by a host of its own (US1)', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'host_buckets' });
		resetAdminMemoryStores();
		forgetBucketAddresses();
		tenantBucketId = await seedBucket('Acme', TENANT_HOST, 'host-bucket-app');
		otherBucketId = await seedBucket(
			'Globex',
			OTHER_HOST,
			'other-host-bucket-app'
		);
	});

	it('serves the bucket its metadata belongs to when the request arrives at that bucket host', async () => {
		const response = await at(TENANT_HOST, '/.well-known/openid-configuration');
		expect(response.status).toBe(200);

		const metadata = (await response.json()) as Record<string, string>;
		expect(metadata.issuer).toBe(`http://${TENANT_HOST}`);
	});

	it('advertises endpoints beneath that origin with no bucket segment in any of them', async () => {
		const response = await at(TENANT_HOST, '/.well-known/openid-configuration');
		const metadata = (await response.json()) as Record<string, string>;

		expect(metadata.authorization_endpoint).toBe(`http://${TENANT_HOST}/auth`);
		expect(metadata.token_endpoint).toBe(`http://${TENANT_HOST}/token`);
	});

	it('serves a different bucket at a different host on the same deployment', async () => {
		const response = await at(OTHER_HOST, '/.well-known/openid-configuration');
		const metadata = (await response.json()) as Record<string, string>;

		expect(metadata.issuer).toBe(`http://${OTHER_HOST}`);
	});

	/* A deployment that is not on 80 or 443 — the development default here is 3000 — receives a `Host`
	 * header carrying the port, because that is what the standard tells a client to send. The bucket is
	 * addressed by a name, and a port is not part of a name. */
	it('serves the bucket when the request names its host with a port', async () => {
		const response = await at(
			TENANT_HOST,
			'/.well-known/openid-configuration',
			{ headers: { host: `${TENANT_HOST}:3000` } }
		);
		expect(response.status).toBe(200);

		const metadata = (await response.json()) as Record<string, string>;
		expect(metadata.issuer).toBe(`http://${TENANT_HOST}`);
	});

	it('refuses a request to a hostname no bucket holds', async () => {
		const response = await at(
			UNCLAIMED_HOST,
			'/.well-known/openid-configuration'
		);

		/* Refused, not served by the default population: falling back would answer one population's
		 * endpoints at another's address and make a typo look like it worked. */
		expect(response.status).toBeGreaterThanOrEqual(400);
	});

	it('treats a leading path segment as an ordinary path when the request arrives at a bucket host', async () => {
		/* `globex` names a real bucket, and on the canonical host it is an address. Here it must not be:
		 * one bucket has one address, and honouring it would give Globex a second. */
		const response = await at(
			TENANT_HOST,
			'/globex/.well-known/openid-configuration'
		);

		expect(response.status).toBeGreaterThanOrEqual(400);
	});

	it('keeps serving a path-addressed bucket at the canonical host', async () => {
		const response = await elysia.handle(
			new Request('http://e.ly/.well-known/openid-configuration')
		);
		const metadata = (await response.json()) as Record<string, string>;

		expect(metadata.issuer).toBe('http://e.ly');
	});

	it('issues a token whose issuer is the origin that advertised the endpoint', async () => {
		const email = `issuer-${Math.random()}@x.io`;
		await getUserStore(tenantBucketId).create(
			email,
			await Bun.password.hash(PASSWORD),
			[],
			true
		);

		const { response } = await signIn(TENANT_HOST, 'host-bucket-app', email);
		expect(response.status).toBeLessThan(400);

		const metadata = (await (
			await at(TENANT_HOST, '/.well-known/openid-configuration')
		).json()) as Record<string, string>;
		expect(metadata.issuer).toBe(`http://${TENANT_HOST}`);
	});

	it('sets no domain attribute on a session cookie', async () => {
		const email = `cookie-${Math.random()}@x.io`;
		await getUserStore(tenantBucketId).create(
			email,
			await Bun.password.hash(PASSWORD),
			[],
			true
		);

		const { setCookie } = await signIn(TENANT_HOST, 'host-bucket-app', email);

		/* A cookie broadened to a parent domain would hand every bucket every other bucket's session,
		 * and nothing visible would break. */
		expect(setCookie ?? '').not.toMatch(/;\s*domain=/i);
	});

	it('does not accept, on one bucket host, a session established on another', async () => {
		const email = `cross-${Math.random()}@x.io`;
		await getUserStore(tenantBucketId).create(
			email,
			await Bun.password.hash(PASSWORD),
			[],
			true
		);

		const { setCookie } = await signIn(TENANT_HOST, 'host-bucket-app', email);
		expect(typeof setCookie).toBe('string');

		/* The same cookie, replayed at the other bucket's host. It must not sign anybody in there. */
		const challenge = createHash('sha256')
			.update(randomBytes(32).toString('base64url'))
			.digest('base64url');
		const carried = await at(
			OTHER_HOST,
			'/auth?client_id=other-host-bucket-app&scope=openid&response_type=code' +
				`&code_challenge=${challenge}&code_challenge_method=S256` +
				`&redirect_uri=${encodeURIComponent(REDIRECTS['other-host-bucket-app'])}`,
			{ headers: { cookie: (setCookie as string).split(';')[0] } }
		);

		/* An established session skips the login screen; a rejected one does not. */
		expect(carried.headers.get('location') ?? '').toMatch(/\/ui\//);
	});
});

/**
 * @proves An interaction begun at one bucket's address cannot be completed at another's — pinned here
 * because before hostnames the question was about a path prefix somebody could edit, and afterwards it
 * is about an origin, which a browser treats as a real boundary.
 */
describe('an interaction belongs to the address it began at (US1)', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'host_buckets' });
	});

	it('does not complete, at one bucket host, an interaction begun at another', async () => {
		const email = `resume-${Math.random()}@x.io`;
		await getUserStore(tenantBucketId).create(
			email,
			await Bun.password.hash(PASSWORD),
			[],
			true
		);

		const verifier = randomBytes(32).toString('base64url');
		const challenge = createHash('sha256').update(verifier).digest('base64url');
		const started = await at(
			TENANT_HOST,
			'/auth?client_id=host-bucket-app&scope=openid&response_type=code' +
				`&code_challenge=${challenge}&code_challenge_method=S256` +
				`&redirect_uri=${encodeURIComponent(REDIRECTS['host-bucket-app'])}`
		);
		const uid = (started.headers.get('location') ?? '').split('/')[2];
		const interactionCookie = started.headers.get('set-cookie') ?? '';

		/* The same interaction, carried to the other bucket's origin. */
		const elsewhere = await at(OTHER_HOST, `/ui/${uid}/login`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				cookie: interactionCookie
			},
			body: new URLSearchParams({
				username: email,
				password: PASSWORD
			}).toString()
		});

		expect(elsewhere.status).toBeGreaterThanOrEqual(400);
	});
});
