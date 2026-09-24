import crypto from 'node:crypto';

import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterEach
} from 'bun:test';

import bootstrap, { seedClient } from '../test_helper.js';
import { mock } from '../fetch_mock.js';
import { saveSettings, superAdminCookie } from '../settings_apply/helpers.js';
import { PAYMENT_TYPE } from './client_edit.config.js';
import { adapter, configStore } from 'lib/adapters/index.js';
import { updateClient } from 'lib/admin/clients/service.ts';
import { configuration } from 'lib/configs/application.js';
import {
	authorizationEncryptionAlgValues,
	authorizationEncryptionEncValues,
	idTokenEncryptionAlgValues,
	idTokenEncryptionEncValues,
	introspectionEncryptionAlgValues,
	introspectionEncryptionEncValues,
	requestObjectEncryptionAlgValues,
	requestObjectEncryptionEncValues,
	userinfoEncryptionAlgValues,
	userinfoEncryptionEncValues
} from 'lib/configs/jwaAlgorithms.js';
import { ATTRIBUTES, BASE_ATTRIBUTES } from 'lib/consts/client_attributes.ts';
import { Claims } from 'lib/helpers/claims.ts';
import { Client } from 'lib/models/client.js';
import { buildRecognizedMetadata } from 'lib/models/client/schema.ts';

// The stored record of a client the case seeded; fails the case when there is none.
async function storedClient(clientId: string) {
	const record = await adapter('Client').find(clientId);
	if (!record) throw new Error(`expected a stored client ${clientId}`);
	return record;
}

const RP = 'https://rp.example.com';
const SECTOR = 'https://sector.example.com';
const SECTOR_PATH = '/sector.json';

function publicJwk() {
	const { publicKey } = crypto.generateKeyPairSync('ec', {
		namedCurve: 'P-256'
	});
	return publicKey.export({ format: 'jwk' });
}

/*
 * Serves the sector identifier document on every retrieval the next steps make. Each interceptor is
 * spent once, and resolving a pairwise client with a sector identifier retrieves it, so a handful are
 * registered rather than counting retrievals the cases do not assert.
 */
function serveSectorDocument(redirectUris: string[]) {
	for (let i = 0; i < 6; i += 1) {
		mock(SECTOR)
			.intercept({ path: SECTOR_PATH })
			.reply(200, JSON.stringify(redirectUris), {
				headers: { 'content-type': 'application/json' }
			});
	}
}

/*
 * Stored records, in the shape storage holds them: base attributes under canonical names, recognised
 * metadata under wire names. Together they carry every attribute a deployment with every capability on
 * recognises — alternatives that cannot share a client (a key set and a key-set URI, the five
 * certificate subjects, the two proof-of-possession requirements) are split across records.
 */
function fixtures(): Record<string, unknown>[] {
	const acr = [...configuration.acrValues][0];

	const rich = {
		clientId: 'edit-rich',
		applicationType: 'web',
		redirectUris: [`${RP}/cb`],
		responseTypes: ['code'],
		responseModes: ['query', 'jwt'],
		grantTypes: [
			'authorization_code',
			'refresh_token',
			'urn:openid:params:grant-type:ciba'
		],
		subjectType: 'pairwise',
		'consent.require': true,
		registeredDynamically: true,
		registrationUsedAt: 1_700_000_100,
		client_id_issued_at: 1_700_000_000,
		client_name: 'Rich',
		client_uri: RP,
		contacts: ['ops@rp.example.com'],
		default_acr_values: [acr],
		default_max_age: 3600,
		id_token_signed_response_alg: 'ES256',
		initiate_login_uri: `${RP}/login`,
		jwks_uri: `${RP}/jwks`,
		logo_uri: `${RP}/logo.png`,
		policy_uri: `${RP}/policy`,
		tos_uri: `${RP}/tos`,
		require_auth_time: true,
		scope: 'openid',
		sector_identifier_uri: `${SECTOR}${SECTOR_PATH}`,
		token_endpoint_auth_method: 'private_key_jwt',
		token_endpoint_auth_signing_alg: 'ES256',
		// The configured encryption algorithms are symmetric, so the key derives from a secret.
		clientSecret: 'a-secret-for-the-symmetric-encryption-keys-0000',
		userinfo_signed_response_alg: 'RS256',
		userinfo_encrypted_response_alg: userinfoEncryptionAlgValues[0],
		userinfo_encrypted_response_enc: userinfoEncryptionEncValues[0],
		introspection_signed_response_alg: 'ES256',
		introspection_encrypted_response_alg: introspectionEncryptionAlgValues[0],
		introspection_encrypted_response_enc: introspectionEncryptionEncValues[0],
		id_token_encrypted_response_alg: idTokenEncryptionAlgValues[0],
		id_token_encrypted_response_enc: idTokenEncryptionEncValues[0],
		authorization_signed_response_alg: 'ES256',
		authorization_encrypted_response_alg: authorizationEncryptionAlgValues[0],
		authorization_encrypted_response_enc: authorizationEncryptionEncValues[0],
		request_object_encryption_alg: requestObjectEncryptionAlgValues[0],
		request_object_encryption_enc: requestObjectEncryptionEncValues[0],
		require_signed_request_object: true,
		post_logout_redirect_uris: [`${RP}/bye`],
		backchannel_logout_uri: `${RP}/logout`,
		backchannel_logout_session_required: true,
		backchannel_token_delivery_mode: 'poll',
		backchannel_user_code_parameter: true,
		dpop_bound_access_tokens: true,
		authorization_details_types: [PAYMENT_TYPE]
	};

	const secret = {
		clientId: 'edit-secret',
		clientSecret: 'a-secret-that-is-long-enough-to-be-realistic-000',
		client_secret_expires_at: 4_102_444_800,
		token_endpoint_auth_method: 'client_secret_basic',
		applicationType: 'web',
		redirectUris: [`${RP}/secret-cb`],
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'urn:openid:params:grant-type:ciba'],
		subjectType: 'public',
		'consent.require': false,
		'authorization.requirePushedAuthorizationRequests': true,
		'requestObject.signingAlg': 'ES256',
		'requestObject.backChannelSigningAlg': 'ES256',
		jwks: { keys: [publicJwk()] },
		backchannel_token_delivery_mode: 'ping',
		backchannel_client_notification_endpoint: `${RP}/ciba`,
		tls_client_certificate_bound_access_tokens: true
	};

	const subjects = {
		tls_client_auth_subject_dn: 'CN=rp.example.com',
		tls_client_auth_san_dns: 'rp.example.com',
		tls_client_auth_san_uri: RP,
		tls_client_auth_san_ip: '192.0.2.1',
		tls_client_auth_san_email: 'rp@example.com'
	};
	const certificates = Object.entries(subjects).map(([name, value]) => ({
		clientId: `edit-${name}`,
		token_endpoint_auth_method: 'tls_client_auth',
		[name]: value,
		use_mtls_endpoint_aliases: true,
		applicationType: 'web',
		redirectUris: [],
		responseTypes: [],
		grantTypes: ['client_credentials'],
		subjectType: 'public'
	}));

	return [rich, secret, ...certificates];
}

/**
 * @proves An administrator or agent editing one field of a client leaves every other attribute of
 * that client as it was, including every attribute the console never displays.
 */
describe('editing a client through the console', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'client_edit' });
	});

	afterEach(() => {
		mock.restore();
	});

	it('leaves every recognised attribute unchanged when only the name is edited', async () => {
		const records = fixtures();
		const carried = new Set(records.flatMap((record) => Object.keys(record)));
		const recognised = [
			...buildRecognizedMetadata(),
			...Object.keys(BASE_ATTRIBUTES),
			'registeredDynamically',
			'registrationUsedAt'
		];
		// The configuration must switch on every capability, or the guard ranges over a subset.
		expect(
			Object.keys(ATTRIBUTES).filter((name) => !recognised.includes(name))
		).toEqual([]);
		expect(recognised.filter((name) => !carried.has(name))).toEqual([]);

		for (const record of records) {
			const clientId = record.clientId as string;
			serveSectorDocument([`${RP}/cb`, `${RP}/jwks`]);
			seedClient(record as { clientId: string });
			const before = await storedClient(clientId);

			await updateClient(clientId, { clientName: 'Renamed' });

			const after = await storedClient(clientId);
			expect(after.client_name).toBe('Renamed');
			for (const [name, value] of Object.entries(before)) {
				if (name === 'client_name') continue;
				expect({ [name]: after[name] }).toEqual({ [name]: value });
			}
		}
	});

	it('keeps the subject identifier of a pairwise client its administrator renames', async () => {
		const [rich] = fixtures();
		const record = { ...rich, clientId: 'edit-pairwise-sub' };
		serveSectorDocument([`${RP}/cb`, `${RP}/jwks`]);
		seedClient(record);
		const subject = async () => {
			const client = await Client.find(record.clientId);
			const claims = await new Claims(client, { sub: 'account-7' })
				.scope('openid')
				.result();
			return claims.sub;
		};
		const before = await subject();

		await updateClient(record.clientId, { clientName: 'Renamed' });

		expect(before).not.toBe('account-7');
		expect(await subject()).toBe(before);
	});

	it('edits the redirect URIs of a client that authenticates with a private key and keeps its key-set URI', async () => {
		seedClient({
			clientId: 'edit-private-key',
			applicationType: 'web',
			redirectUris: [`${RP}/one`],
			responseTypes: ['code'],
			grantTypes: ['authorization_code'],
			subjectType: 'public',
			token_endpoint_auth_method: 'private_key_jwt',
			jwks_uri: `${RP}/jwks`
		});

		const view = await updateClient('edit-private-key', {
			redirectUris: [`${RP}/two`]
		});

		expect(view.redirectUris).toEqual([`${RP}/two`]);
		const stored = await storedClient('edit-private-key');
		expect(stored.jwks_uri).toBe(`${RP}/jwks`);
	});

	it('refuses an edit that leaves a client with response types but no redirect URIs, and keeps the record', async () => {
		seedClient({
			clientId: 'edit-refused',
			applicationType: 'web',
			redirectUris: [`${RP}/kept`],
			responseTypes: ['code'],
			grantTypes: ['authorization_code'],
			subjectType: 'public',
			token_endpoint_auth_method: 'none'
		});
		const before = await adapter('Client').find('edit-refused');

		await expect(
			updateClient('edit-refused', { redirectUris: [] })
		).rejects.toMatchObject({
			error_description: 'redirectUris must contain members'
		});

		expect(await adapter('Client').find('edit-refused')).toEqual(before);
	});
});

/**
 * @proves A change to a pairwise client is checked against its sector identifier document when it is
 * made, not left to fail the next time somebody uses the client.
 */
describe('editing a pairwise client with a sector identifier', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'client_edit' });
	});

	afterEach(() => {
		mock.restore();
	});

	it('refuses a redirect URI the sector identifier document does not list, and keeps the record', async () => {
		seedClient({
			clientId: 'edit-sector',
			applicationType: 'web',
			redirectUris: [`${RP}/cb`],
			responseTypes: ['code'],
			grantTypes: ['authorization_code'],
			subjectType: 'pairwise',
			sector_identifier_uri: `${SECTOR}${SECTOR_PATH}`,
			token_endpoint_auth_method: 'none'
		});
		serveSectorDocument([`${RP}/cb`]);
		const before = await adapter('Client').find('edit-sector');

		await expect(
			updateClient('edit-sector', {
				redirectUris: [`${RP}/cb`, `${RP}/unlisted`]
			})
		).rejects.toMatchObject({
			error_description:
				'all registered redirectUris must be included in the sector_identifier_uri response'
		});

		expect(await adapter('Client').find('edit-sector')).toEqual(before);
	});
});

/**
 * @proves An administrator editing a client after switching a capability off stores a client the
 * deployment can still read, without the attributes that capability gave meaning to.
 */
describe('editing a client after a capability is switched off', () => {
	let cookie: string;

	beforeEach(async () => {
		await bootstrap(import.meta.url, { config: 'client_edit' });
		await configStore.set({});
		cookie = await superAdminCookie();
	});

	it('drops the attributes of the switched-off capability and keeps the rest', async () => {
		seedClient({
			clientId: 'edit-capability-off',
			applicationType: 'web',
			redirectUris: [`${RP}/cb`],
			responseTypes: ['code'],
			grantTypes: ['authorization_code'],
			subjectType: 'public',
			token_endpoint_auth_method: 'none',
			default_max_age: 900,
			backchannel_logout_uri: `${RP}/logout`,
			backchannel_logout_session_required: true
		});
		const saved = await saveSettings(cookie, {
			'backchannelLogout.enabled': false
		});
		expect(saved.status).toBe(200);

		await updateClient('edit-capability-off', { clientName: 'Renamed' });

		const stored = await storedClient('edit-capability-off');
		expect(stored.backchannel_logout_uri).toBeUndefined();
		expect(stored.backchannel_logout_session_required).toBeUndefined();
		expect(stored.default_max_age).toBe(900);
		expect((await Client.find('edit-capability-off')).clientName).toBe(
			'Renamed'
		);
	});
});
