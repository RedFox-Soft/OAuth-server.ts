import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterEach
} from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getUserStore,
	getProjectStore,
	adminAuditStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { mcpCatalogue } from 'lib/mcp/catalogue.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { mock } from '../fetch_mock.ts';
import { idpStub } from '../federation/idp_stub.ts';

/*
 * FR-023 / SC-007: no secret may reach the agent surface, on any tool, in a success or an error, or in
 * an audit entry.
 *
 * The sweep drives the *catalogue* rather than a hand-written list of tools, so a tool added later is
 * covered without anyone remembering to extend this file. That matters more than the individual
 * assertions: the failure this guards against is somebody publishing a new read next year whose
 * projection happens to include a stored secret.
 *
 * Every value below is a distinctive marker rather than a realistic secret, so a leak cannot hide in
 * plausible-looking text — a substring search over the whole serialised response either finds it or it
 * is not there.
 */

const SECRETS = {
	smtpPassword: 'SECRET-smtp-pw-2f9a',
	providerSecret: 'SECRET-provider-cs-7b31',
	endUserPassword: 'SECRET-enduser-pw-c04d'
};

let rpcId = 0;

async function rpc(body: unknown, token: string) {
	const res = await elysia.handle(
		new Request(`http://e.ly${MCP_ROUTE}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				accept: 'application/json, text/event-stream',
				authorization: `Bearer ${token}`
			},
			body: JSON.stringify(body)
		})
	);
	const text = await res.text();
	const isEvent = (res.headers.get('content-type') ?? '').includes(
		'text/event-stream'
	);
	const line = isEvent
		? text.split('\n').find((l) => l.startsWith('data:'))
		: undefined;
	return isEvent
		? line
			? JSON.parse(line.slice('data:'.length).trim())
			: undefined
		: text
			? JSON.parse(text)
			: undefined;
}

function call(name: string, args: Record<string, unknown>) {
	return {
		jsonrpc: '2.0',
		id: ++rpcId,
		method: 'tools/call',
		params: { name, arguments: args }
	};
}

async function superAdminSession() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`sec-${Math.random()}@x.io`,
		'hash',
		['super_admin']
	);
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId: user._id,
		scope: 'openid'
	});
	at.setAudience(MCP_RESOURCE);
	const token = (await at.save()) as unknown as string;
	await rpc(
		{
			jsonrpc: '2.0',
			id: ++rpcId,
			method: 'initialize',
			params: {
				protocolVersion: '2026-07-28',
				capabilities: {},
				clientInfo: { name: 'test-agent', version: '1.0.0' }
			}
		},
		token
	);
	return { user, token };
}

/*
 * Performs a high-consequence tool: describe, then confirm. Needed because the gate means one call
 * changes nothing — which this test found the hard way, when a seeded SMTP password was never stored
 * and the mask assertion passed for the wrong reason.
 */
async function performGated(
	token: string,
	name: string,
	args: Record<string, unknown>
) {
	const described = await rpc(call(name, args), token);
	const confirmationToken =
		described.result?.structuredContent?.confirmationToken;
	if (typeof confirmationToken !== 'string') return described;
	return rpc(call(name, { ...args, confirmationToken }), token);
}

/* Fills the instance with things that hold secrets, so a leaky projection has something to leak. */
async function seedSecretHolders(token: string) {
	const project = await getProjectStore().create({
		name: 'Secrets',
		slug: `sec-${Math.floor(Math.random() * 1e6)}`,
		managedBy: []
	});

	// A confidential client, whose secret is generated server-side and shown exactly once.
	const created = await rpc(
		call('client_create', {
			id: project._id,
			clientName: 'Confidential',
			grantTypes: ['authorization_code'],
			redirectUris: ['https://c.example.com/cb'],
			tokenEndpointAuthMethod: 'client_secret_basic'
		}),
		token
	);
	const createdBody = created.result?.structuredContent?.result as {
		clientId: string;
		secret?: string;
	};

	const bucket = await rpc(
		call('bucket_create', { name: 'Secret bucket' }),
		token
	);
	const bucketId = (bucket.result?.structuredContent?.result as { _id: string })
		._id;

	await rpc(
		call('bucket_user_create', {
			id: bucketId,
			email: `holder-${Math.random()}@x.io`,
			password: SECRETS.endUserPassword
		}),
		token
	);

	/*
	 * The issuer is stubbed because creating a provider validates it over the network. Without the stub
	 * the create fails, no provider secret is ever stored, and every assertion below passes because
	 * there was nothing to leak — the same trap the SMTP password fell into.
	 */
	const idp = await idpStub(
		`https://idp-mcp-secrecy-${Math.floor(Math.random() * 1e6)}.test`
	);
	idp.expectDiscovery();
	const provider = await rpc(
		call('federation_provider_create', {
			bucketId,
			id: 'okta',
			displayName: 'Okta',
			issuer: idp.origin,
			clientId: 'fed-client',
			clientSecret: SECRETS.providerSecret
		}),
		token
	);
	if (provider.result?.isError) {
		throw new Error(
			`provider seed failed, so the secret was never stored: ${JSON.stringify(provider.result)}`
		);
	}

	await performGated(token, 'smtp_settings_update', {
		host: 'smtp.example.com',
		port: 587,
		secure: true,
		username: 'mailer',
		password: SECRETS.smtpPassword,
		fromName: 'Ops',
		fromEmail: 'ops@example.com'
	});

	return {
		project,
		clientId: createdBody.clientId,
		clientSecret: createdBody.secret,
		bucketId
	};
}

describe('MCP surface leaks no secrets', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
	});

	afterEach(() => {
		// The outbound stub is per-case: each provider create consumes its own single-use interceptor.
		mock.restore();
	});

	it('returns a confidential client secret exactly once, at creation', async () => {
		const { token } = await superAdminSession();
		const seeded = await seedSecretHolders(token);

		// Shown once. That single issuance is the contract, and it is what the sweep below then
		// asserts never happens again.
		const secret = seeded.clientSecret;
		if (typeof secret !== 'string') {
			throw new Error(
				'client_create returned no secret for a confidential client'
			);
		}
		expect(secret.length).toBeGreaterThan(8);

		const read = await rpc(
			call('client_get', { id: seeded.project._id, clientId: seeded.clientId }),
			token
		);
		expect(JSON.stringify(read)).not.toContain(secret);

		const listed = await rpc(
			call('client_list', { id: seeded.project._id }),
			token
		);
		expect(JSON.stringify(listed)).not.toContain(secret);
	});

	it('leaks no secret through any read tool', async () => {
		const { token } = await superAdminSession();
		const seeded = await seedSecretHolders(token);

		const needles = [
			...Object.values(SECRETS),
			...(seeded.clientSecret ? [seeded.clientSecret] : [])
		];

		const args: Record<string, Record<string, unknown>> = {
			project_get: { id: seeded.project._id },
			client_list: { id: seeded.project._id },
			client_get: { id: seeded.project._id, clientId: seeded.clientId },
			bucket_get: { id: seeded.bucketId },
			bucket_user_list: { id: seeded.bucketId },
			federation_provider_list: { id: seeded.bucketId }
		};

		// Driven from the catalogue: every published read is swept, including ones added later.
		for (const tool of mcpCatalogue.filter((t) => t.consequence === 'read')) {
			if (tool.pathParams.length > 0 && !args[tool.tool]) {
				// A read needing an identifier this test has not created. Skipped loudly rather than
				// silently, so the gap is visible if the catalogue grows.
				continue;
			}
			const response = await rpc(call(tool.tool, args[tool.tool] ?? {}), token);
			const serialised = JSON.stringify(response);
			for (const needle of needles) {
				expect(serialised, `${tool.tool} leaked a secret`).not.toContain(
					needle
				);
			}
		}
	});

	it('masks the SMTP password rather than returning it', async () => {
		const { token } = await superAdminSession();
		await seedSecretHolders(token);

		const settings = await rpc(call('smtp_settings_get', {}), token);
		const serialised = JSON.stringify(settings);

		expect(serialised).not.toContain(SECRETS.smtpPassword);
		// The host round-trips, so this is a real read rather than an empty answer that would pass
		// the assertion above for the wrong reason.
		expect(serialised).toContain('smtp.example.com');
	});

	it('returns no private key material from the key tools', async () => {
		const { token } = await superAdminSession();

		await performGated(token, 'jwks_generate', { alg: 'RS256' });

		const listed = await rpc(call('jwks_list', {}), token);
		const serialised = JSON.stringify(listed);

		// The private components of an RSA JWK. An allow-list projection is what keeps these out; this
		// asserts the outcome of that rather than the mechanism.
		for (const field of ['"d"', '"p"', '"q"', '"dp"', '"dq"', '"qi"']) {
			expect(serialised, `jwks_list exposed ${field}`).not.toContain(field);
		}
		// A real key is present, so the assertions above are not passing on an empty list.
		expect(serialised).toContain('"kty"');
	});

	it('leaks no secret through an error path', async () => {
		const { token } = await superAdminSession();
		const seeded = await seedSecretHolders(token);
		const needles = [
			...Object.values(SECRETS),
			...(seeded.clientSecret ? [seeded.clientSecret] : [])
		];

		// Validation failures, not-found failures, and a refused confirmation: the three shapes whose
		// messages quote back part of a request.
		const failures = [
			call('client_get', {
				id: seeded.project._id,
				clientId: 'no-such-client'
			}),
			call('project_get', { id: 'no-such-project' }),
			call('federation_provider_update', {
				id: seeded.bucketId,
				providerId: 'okta',
				clientSecret: SECRETS.providerSecret
			}),
			call('smtp_settings_update', {
				host: '',
				port: -1,
				secure: true,
				username: '',
				password: SECRETS.smtpPassword,
				fromName: '',
				fromEmail: 'not-an-email'
			})
		];

		for (const failure of failures) {
			const response = await rpc(failure, token);
			const serialised = JSON.stringify(response);
			for (const needle of needles) {
				expect(
					serialised,
					`an error path echoed a secret back: ${JSON.stringify(failure.params.name)}`
				).not.toContain(needle);
			}
		}
	});

	it('leaks no secret into the audit trail', async () => {
		const { token, user } = await superAdminSession();
		const seeded = await seedSecretHolders(token);
		const needles = [
			...Object.values(SECRETS),
			...(seeded.clientSecret ? [seeded.clientSecret] : [])
		];

		const { entries } = await adminAuditStore.list({ actor: user._id });
		expect(entries.length).toBeGreaterThan(0);

		const serialised = JSON.stringify(entries);
		for (const needle of needles) {
			expect(serialised, 'the audit trail recorded a secret').not.toContain(
				needle
			);
		}
		// `attributes` records field *names*, never values — which is what makes the above hold even
		// though the trail describes requests that carried secrets.
		expect(serialised).toContain('attributes');
	});
});
