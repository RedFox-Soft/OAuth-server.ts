import { shownAccount } from '../consent_form.js';
import { createHash, randomBytes } from 'node:crypto';
import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, { bindClientToBucket } from '../test_helper.ts';
import {
	getBucketStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { elysia } from 'lib/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { decodeJwt } from 'jose';
import { Type } from '@sinclair/typebox';
import { shaped } from 'test/shape.ts';

const PASSWORD = 'correct horse battery';

/* The test instance is `http://e.ly`, so a project's subdomain is one label beneath it. */
const ACME = 'acme.e.ly';
const BETA = 'beta.e.ly';

const Metadata = Type.Object({ issuer: Type.String() });
const Tokens = Type.Object({ id_token: Type.String() });

const REDIRECTS: Record<string, string> = {
	'subdomain-app': 'http://e.ly/subdomain/callback',
	'other-subdomain-app': 'http://e.ly/other-subdomain/callback',
	'path-project-app': 'http://e.ly/path-project/callback'
};

let acmeId: string;
let betaId: string;

function at(host: string, path: string, init: RequestInit = {}) {
	return elysia.handle(
		new Request(`http://${host}${path}`, { redirect: 'manual', ...init })
	);
}

async function seedProject(
	name: string,
	slug: string,
	clientId: string,
	subdomain: boolean
): Promise<string> {
	const bucket = await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name,
		slug,
		...(subdomain ? { subdomain: true as const } : {})
	});
	await bindClientToBucket(clientId, bucket._id);
	return bucket._id;
}

async function endUser(bucketId: string): Promise<string> {
	const email = `user-${Math.random()}@x.io`;
	await getUserStore(bucketId).create(
		email,
		await Bun.password.hash(PASSWORD),
		true
	);
	return email;
}

function cookiesOf(res: Response): string[] {
	return res.headers
		.getSetCookie()
		.filter((cookie) => !cookie.includes('Max-Age=0'))
		.map((cookie) => cookie.split(';')[0]);
}

function authorizePath(clientId: string, challenge: string): string {
	return (
		`/auth?client_id=${clientId}&scope=openid&response_type=code` +
		`&code_challenge=${challenge}&code_challenge_method=S256` +
		`&redirect_uri=${encodeURIComponent(REDIRECTS[clientId])}`
	);
}

/* A sign-in carried through the login and consent screens at one host, back to the client. */
async function signIn(host: string, clientId: string, email: string) {
	const verifier = randomBytes(32).toString('base64url');
	const challenge = createHash('sha256').update(verifier).digest('base64url');
	const started = await at(host, authorizePath(clientId, challenge));
	const uid = (started.headers.get('location') ?? '').split('/')[2];

	const submitted = await at(host, `/ui/${uid}/login`, {
		method: 'POST',
		headers: {
			'content-type': 'application/x-www-form-urlencoded',
			cookie: started.headers.get('set-cookie') ?? ''
		},
		body: new URLSearchParams({
			username: email,
			password: PASSWORD
		}).toString()
	});
	const consentUid = (submitted.headers.get('location') ?? '').split('/')[2];
	const allowed = await at(host, `/ui/${consentUid}/consent`, {
		method: 'POST',
		headers: {
			'content-type': 'application/x-www-form-urlencoded',
			cookie: cookiesOf(submitted).join('; ')
		},
		body: new URLSearchParams({
			action: 'allow',
			accountId: await shownAccount(consentUid)
		}).toString()
	});
	const setCookies = allowed.headers.getSetCookie();
	const session = cookiesOf(allowed).find((c) => c.startsWith('_session'));
	if (!session) throw new Error('expected a session cookie');
	return {
		session,
		setCookies,
		verifier,
		location: allowed.headers.get('location') ?? ''
	};
}

/* Whether a held session cookie signs its holder in at a host without the login screen. */
async function signedInAt(
	host: string,
	clientId: string,
	session: string
): Promise<boolean> {
	const challenge = createHash('sha256')
		.update(randomBytes(32).toString('base64url'))
		.digest('base64url');
	const response = await at(host, authorizePath(clientId, challenge), {
		headers: { cookie: session }
	});
	return (response.headers.get('location') ?? '').includes('code=');
}

/**
 * @proves A project addressed by a subdomain of the instance is served at that origin and nowhere else: its
 * metadata, endpoints, authorization responses and tokens name that origin; it does not also answer at its
 * path; a subdomain no project holds is refused; and its sign-ins stay on its own origin.
 */
describe('a project addressed by a subdomain of the instance', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'subdomain_projects' });
		resetAdminMemoryStores();
		forgetBucketAddresses();
		acmeId = await seedProject('Acme', 'acme', 'subdomain-app', true);
		betaId = await seedProject('Beta', 'beta', 'other-subdomain-app', true);
		await seedProject('Gamma', 'gamma', 'path-project-app', false);
	});

	it('names its subdomain origin as issuer in its metadata', async () => {
		const response = await at(ACME, '/.well-known/openid-configuration');
		expect(response.status).toBe(200);

		expect(shaped(Metadata, await response.json()).issuer).toBe(
			`http://${ACME}`
		);
	});

	it('serves every endpoint its metadata advertises at that origin', async () => {
		const metadata = (await (
			await at(ACME, '/.well-known/openid-configuration')
		).json()) as Record<string, unknown>;
		const advertised = Object.entries(metadata)
			.filter(
				([key, value]) =>
					typeof value === 'string' &&
					(key.endsWith('_endpoint') || key === 'jwks_uri')
			)
			.map(([, value]) => new URL(String(value)));

		expect(advertised.length).toBeGreaterThan(0);
		const missing: string[] = [];
		for (const url of advertised) {
			expect(url.host).toBe(ACME);
			/* Some endpoints take only POST, so an endpoint is missing only when neither method finds it. */
			const answers = await Promise.all(
				['GET', 'POST'].map(
					async (method) => (await at(ACME, url.pathname, { method })).status
				)
			);
			if (answers.every((status) => status === 404)) missing.push(url.pathname);
		}
		expect(missing).toEqual([]);
	});

	it('names its subdomain origin in the authorization response and the ID token', async () => {
		const { location, verifier } = await signIn(
			ACME,
			'subdomain-app',
			await endUser(acmeId)
		);
		const callback = new URL(location);
		expect(callback.searchParams.get('iss')).toBe(`http://${ACME}`);

		const exchanged = await at(ACME, '/token', {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				grant_type: 'authorization_code',
				code: callback.searchParams.get('code') ?? '',
				redirect_uri: REDIRECTS['subdomain-app'],
				client_id: 'subdomain-app',
				code_verifier: verifier
			}).toString()
		});
		expect(exchanged.status).toBe(200);
		const { id_token } = shaped(Tokens, await exchanged.json());
		expect(decodeJwt(id_token).iss).toBe(`http://${ACME}`);
	});

	it('is not served at its path on the instance host', async () => {
		const answers = await Promise.all(
			[
				'/acme/.well-known/openid-configuration',
				'/.well-known/openid-configuration/acme',
				'/.well-known/oauth-authorization-server/acme',
				'/acme/jwks'
			].map(async (path) => (await at('e.ly', path)).status)
		);

		expect(answers).toEqual([404, 404, 404, 404]);
	});

	it('refuses a subdomain no project holds rather than serving the default project there', async () => {
		const response = await at(
			'nobody.e.ly',
			'/.well-known/openid-configuration'
		);

		expect(response.status).toBe(404);
	});

	it('refuses a name two labels beneath the instance', async () => {
		const response = await at(
			`deeper.${ACME}`,
			'/.well-known/openid-configuration'
		);

		expect(response.status).toBe(404);
	});

	it('does not serve a path project at its slug as a subdomain', async () => {
		const response = await at(
			'gamma.e.ly',
			'/.well-known/openid-configuration'
		);

		expect(response.status).toBe(404);
	});

	it('names its session cookie without a project suffix and without a domain', async () => {
		const { setCookies } = await signIn(
			ACME,
			'subdomain-app',
			await endUser(acmeId)
		);
		const session = setCookies.find((cookie) => cookie.startsWith('_session'));

		expect(session ?? '').toMatch(/^_session=/);
		expect(session ?? '').not.toMatch(/;\s*domain=/i);
	});

	it('keeps sign-ins at two subdomain projects apart, each held at its own origin', async () => {
		const atAcme = await signIn(ACME, 'subdomain-app', await endUser(acmeId));
		const atBeta = await signIn(
			BETA,
			'other-subdomain-app',
			await endUser(betaId)
		);

		expect([
			await signedInAt(ACME, 'subdomain-app', atAcme.session),
			await signedInAt(BETA, 'other-subdomain-app', atBeta.session),
			await signedInAt(BETA, 'other-subdomain-app', atAcme.session)
		]).toEqual([true, true, false]);
	});

	it('does not complete, at one subdomain, an interaction begun at another', async () => {
		const email = await endUser(acmeId);
		const challenge = createHash('sha256')
			.update(randomBytes(32).toString('base64url'))
			.digest('base64url');
		const started = await at(ACME, authorizePath('subdomain-app', challenge));
		const uid = (started.headers.get('location') ?? '').split('/')[2];

		const elsewhere = await at(BETA, `/ui/${uid}/login`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				cookie: started.headers.get('set-cookie') ?? ''
			},
			body: new URLSearchParams({
				username: email,
				password: PASSWORD
			}).toString()
		});

		expect(elsewhere.status).toBeGreaterThanOrEqual(400);
	});
});
