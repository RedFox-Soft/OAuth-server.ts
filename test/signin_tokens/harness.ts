import { spyOn } from 'bun:test';

import { OIDCContext } from 'lib/helpers/oidc_context.js';
import {
	getBucketStore,
	getConnectedAccountStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { UserBucket } from 'lib/adapters/types.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import type {
	ConnectedAccount,
	ConnectedService
} from 'lib/connected_services/types.ts';
import type { FederationProvider } from 'lib/federation/types.ts';
import { present } from '../shape.ts';
import { defaultBucket } from '../connected_apps/helpers.ts';
import { seedAccount, type Setup } from '../test_helper.js';
import { signIn, type SignedIn } from '../upstream_tokens/harness.ts';
import { idpStub, type IdpStub } from '../federation/idp_stub.ts';
import {
	provider as federationProvider,
	startInteraction,
	walk
} from '../federation/harness.ts';

/*
 * A person signing in to the default project through a sign-in provider that may be linked to a connected service
 * (specs/120), driven through the real three legs with the federation suite's provider stub. The service is an
 * OpenID Connect one at the stub's own issuer with the same client id, so a link between them is accepted.
 */

export const CLIENT = 'keep-app';
export const PROVIDER_ID = 'acme-sso';
export const SERVICE_ID = 'acme-files';
export const SERVICE_SCOPES = ['files.read', 'files.write'];

export interface Linked {
	idp: IdpStub;
	service: ConnectedService;
	provider: FederationProvider;
}

let counter = 0;

/*
 * One origin per call, because the stub's discovery and key caches are per URL (test/federation/idp_stub.ts rule 1);
 * the default project's sign-in providers and connected services are replaced by this one pair.
 */
export async function linkedProject(
	options: {
		linked?: boolean;
		/* False for a case that never signs in, so no discovery answer is left waiting. */
		signsIn?: boolean;
		provider?: Partial<FederationProvider>;
		service?: Partial<ConnectedService>;
	} = {}
): Promise<Linked> {
	counter += 1;
	const idp = await idpStub(`https://idp-keep-${counter}.test`);
	if (options.signsIn !== false) idp.expectDiscovery();
	const provider = federationProvider(idp.origin, {
		id: PROVIDER_ID,
		emailTrusted: true,
		...options.provider
	});
	const now = new Date().toISOString();
	const service: ConnectedService = {
		id: SERVICE_ID,
		kind: 'oidc',
		issuer: idp.origin,
		clientId: provider.clientId,
		clientSecret: 'stub-secret',
		scopes: SERVICE_SCOPES,
		displayName: 'Acme Files',
		applications: ['agent'],
		...(options.linked === false ? {} : { signInProviderId: PROVIDER_ID }),
		createdAt: now,
		updatedAt: now,
		...options.service
	};
	await defaultBucket();
	await getBucketStore().update(DEFAULT_BUCKET_ID, {
		federation: [provider],
		connectedServices: [service]
	});
	return { idp, service, provider };
}

export async function project(): Promise<UserBucket> {
	return present(await getBucketStore().find(DEFAULT_BUCKET_ID), 'the project');
}

let people = 0;

/* A fresh upstream person for each sign-in that should be a new account. */
export function upstreamPerson(): Record<string, unknown> {
	people += 1;
	return {
		sub: `upstream-person-${people}`,
		email: `keeper${people}@example.com`,
		email_verified: true
	};
}

/*
 * Signs a person in through the provider, which answers with `claims` and, over its defaults, `tokenResponse`.
 * Answers the three legs and the account the address belongs to, once the sign-in has made or found it.
 */
export async function signInThrough(
	linked: Linked,
	claims: Record<string, unknown>,
	tokenResponse: Record<string, unknown> = {
		access_token: 'kept-access-token',
		refresh_token: 'kept-refresh-token',
		expires_in: 3600,
		scope: ['openid', 'email', 'profile', ...SERVICE_SCOPES].join(' ')
	}
) {
	const { uid, cookie } = await startInteraction(CLIENT);
	const legs = await walk(uid, cookie, {
		idp: linked.idp,
		claims,
		tokenResponse
	});
	const user = await getUserStore(DEFAULT_BUCKET_ID).findByEmail(
		String(claims.email)
	);
	return { ...legs, uid, cookie, accountId: user?._id };
}

export async function keptAccounts(
	accountId: string
): Promise<ConnectedAccount[]> {
	return getConnectedAccountStore().listByAccount(DEFAULT_BUCKET_ID, accountId);
}

/*
 * The agent signed in to by the person, as in specs/118's suites; its prompts are skipped for this sign-in only, and
 * the person's record is put back afterwards, since the harness's sign-in seeds the account afresh.
 */
export async function agentFor(
	setup: Setup,
	accountId: string
): Promise<SignedIn> {
	const store = getUserStore(DEFAULT_BUCKET_ID);
	const { _id, ...stored } = present(await store.find(accountId), 'the person');
	const prompts = spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(
		false
	);
	try {
		return await signIn(setup, 'agent', accountId);
	} finally {
		prompts.mockRestore();
		seedAccount(_id, stored, DEFAULT_BUCKET_ID);
	}
}
