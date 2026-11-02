import { Type } from '@sinclair/typebox';

import { agent, redirectParameter, type Setup } from '../test_helper.js';
import { AuthorizationRequest } from '../AuthorizationRequest.js';
import {
	getBucketStore,
	getConnectedAccountStore
} from 'lib/adapters/index.ts';
import type { UserBucket } from 'lib/adapters/types.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import epochTime from 'lib/helpers/epoch_time.js';
import { AccessToken } from 'lib/models/access_token.js';
import { grantsIn } from 'lib/end_users/sessions.js';
import {
	Grant,
	connectedAccountKey,
	connectedServiceKey
} from 'lib/models/grant.js';
import type {
	ConnectedAccount,
	ConnectedService
} from 'lib/connected_services/types.ts';
import { present, shaped } from '../shape.js';
import { addService, seededAccount } from '../connected_services/harness.ts';

/*
 * An agent obtaining a person's upstream token (specs/118), driven through the real token endpoint: the person signs
 * in to the agent with the code flow, and the agent exchanges the access token it got. The allow-list and the
 * person's use consent are written straight to the records the surfaces write, for cases about the exchange itself.
 */

export const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
/* The scope an API declared in these specs recognises. */
export const API_SCOPE = 'repos';
export const ACCESS_TOKEN_TYPE =
	'urn:ietf:params:oauth:token-type:access_token';

export const SECRETS: Partial<Record<string, string>> = {
	agent: 'agent-secret',
	'other-agent': 'other-agent-secret',
	'mcp-server': 'mcp-server-secret',
	'self-registered': 'self-registered-secret'
};

export const Exchanged = Type.Object({
	access_token: Type.String(),
	issued_token_type: Type.String(),
	token_type: Type.String(),
	expires_in: Type.Optional(Type.Number()),
	scope: Type.Optional(Type.String()),
	refresh_token: Type.Optional(Type.String())
});

export const Refusal = Type.Object({
	error: Type.String(),
	error_description: Type.Optional(Type.String()),
	reason: Type.Optional(Type.String()),
	/* The labels an agent may choose from (specs/119). */
	accounts: Type.Optional(Type.Array(Type.String()))
});

export async function project(): Promise<UserBucket> {
	return present(await getBucketStore().find(DEFAULT_BUCKET_ID), 'the project');
}

/* A GitHub service on the default project, allowing `applications` to obtain its tokens. */
export async function githubService(
	applications: string[] = ['agent'],
	overrides: Partial<ConnectedService> = {}
): Promise<ConnectedService> {
	return addService({
		kind: 'catalogue',
		catalogueId: 'github',
		scopes: ['repo', 'read:user'],
		displayName: 'GitHub',
		applications,
		...overrides
	});
}

/* An account of `accountId` at `service`, with a token that is good for an hour unless said otherwise. */
export async function connected(
	accountId: string,
	service: ConnectedService,
	fields: Partial<ConnectedAccount> = {}
): Promise<ConnectedAccount> {
	return seededAccount({ accountId, bucket: await project() }, service, {
		scopes: ['repo', 'read:user'],
		accessTokenExpiresAt: epochTime() + 3600,
		refreshedAt: epochTime(),
		...fields
	});
}

export interface SignedIn {
	accessToken: string;
	grantId: string;
}

/*
 * The use of every account the person has, and every service, already answered "no" on the grant the sign-in made,
 * as a person who went through the consent screen and ticked nothing would leave it: these specs are about the
 * exchange, and a case allows what it needs afterwards. The consent screen has its own spec.
 */
async function answeredBefore(accountId: string, clientId: string) {
	const bucket = await project();
	const accounts = await getConnectedAccountStore().listByAccount(
		bucket._id,
		accountId
	);
	const keys = [
		...(bucket.connectedServices ?? []).map((service) =>
			connectedServiceKey(service.id)
		),
		...accounts.map((account) => connectedAccountKey(account._id))
	];
	for (const grant of await grantsIn(bucket._id, accountId)) {
		if (grant.payload.clientId !== clientId) continue;
		for (const key of keys) {
			if (grant.connectedConsent(key) === undefined)
				grant.declineConnected(key);
		}
		await grant.save();
	}
}

/* The person signs in to `clientId` with the code flow, for `resource` when given; answers its access token. */
export async function signIn(
	setup: Setup,
	clientId: string,
	accountId: string,
	resource?: string
): Promise<SignedIn> {
	const scope = resource ? `openid ${API_SCOPE}` : 'openid';
	const cookie = await setup.login({
		scope,
		accountId,
		...(resource ? { resources: { [resource]: API_SCOPE } } : {})
	});
	await answeredBefore(accountId, clientId);
	const request = new AuthorizationRequest({
		client_id: clientId,
		scope,
		prompt: 'consent',
		...(resource ? { resource: [resource] } : {})
	});
	const auth = await agent.auth.get({
		query: request.params,
		headers: { cookie }
	});
	const code = redirectParameter(auth.response, 'code');
	/* RFC 8707 §2.2: the token request names the API too, or the token is for the userinfo endpoint. */
	const { data } = resource
		? await agent.token.post(
				{
					code: typeof code === 'string' ? code : '',
					grant_type: 'authorization_code',
					code_verifier: request.code_verifier,
					redirect_uri: request.params.redirect_uri,
					resource
				},
				{ headers: request.basicAuthHeader }
			)
		: await request.getToken(code);
	const { access_token } = shaped(
		Type.Object({ access_token: Type.String() }),
		data
	);
	/* A JWT access token is not stored and names no grant: the person's grant to the agent is the one just made. */
	if (access_token.split('.').length === 3) {
		const grants = (await grantsIn(DEFAULT_BUCKET_ID, accountId)).filter(
			(grant) => grant.payload.clientId === clientId
		);
		return {
			accessToken: access_token,
			grantId: present(grants.at(-1)?.jti, 'a grant')
		};
	}
	const stored = present(
		await AccessToken.tryFind(access_token),
		'the access token'
	);
	return {
		accessToken: access_token,
		grantId: present(stored.payload.grantId, 'a grant')
	};
}

/* The person's answer about `key` on the grant, as the consent screen or the account page records it. */
export async function consent(
	grantId: string,
	key: string,
	answer: 'allowed' | 'declined' = 'allowed'
): Promise<void> {
	const grant = present(await Grant.tryFind(grantId), 'the grant');
	if (answer === 'allowed') grant.allowConnected(key);
	else grant.declineConnected(key);
	await grant.save();
}

export function allowAccount(grantId: string, record: ConnectedAccount) {
	return consent(grantId, connectedAccountKey(record._id));
}

export function allowService(grantId: string, service: ConnectedService) {
	return consent(grantId, connectedServiceKey(service.id));
}

export interface ExchangeRequest {
	subjectToken: string;
	audience?: string | string[];
	clientId?: string;
	/* `null` presents the client id alone, as an application that does not authenticate does. */
	secret?: string | null;
	loginHint?: string;
	scope?: string;
	resource?: string;
	subjectTokenType?: string;
	dpop?: string;
}

/* The contract's request at the root token endpoint (contracts/token-exchange.md). */
export function exchange(request: ExchangeRequest) {
	const {
		subjectToken,
		audience,
		clientId = 'agent',
		secret = SECRETS[clientId],
		loginHint,
		scope,
		resource,
		subjectTokenType = ACCESS_TOKEN_TYPE,
		dpop
	} = request;
	return agent.token.post(
		{
			grant_type: EXCHANGE,
			subject_token: subjectToken,
			subject_token_type: subjectTokenType,
			requested_token_type: ACCESS_TOKEN_TYPE,
			...(audience === undefined ? {} : { audience }),
			...(loginHint === undefined ? {} : { login_hint: loginHint }),
			...(scope === undefined ? {} : { scope }),
			...(resource === undefined ? {} : { resource }),
			...(secret === null ? { client_id: clientId } : {})
		},
		{
			headers: {
				...(secret === null || secret === undefined
					? {}
					: AuthorizationRequest.basicAuthHeader(clientId, secret)),
				...(dpop ? { dpop } : {})
			}
		}
	);
}

type Answer = Awaited<ReturnType<typeof exchange>>;

export function granted(answer: Answer) {
	if (answer.status !== 200) {
		throw new Error(
			`expected the upstream token, got ${String(answer.status)} ${JSON.stringify(answer.error?.value)}`
		);
	}
	return shaped(Exchanged, answer.data);
}

export function refused(answer: Answer, status = 400) {
	if (answer.status !== status) {
		throw new Error(
			`expected a ${String(status)} refusal, got ${String(answer.status)} ${JSON.stringify(answer.data)}`
		);
	}
	return shaped(Refusal, answer.error?.value);
}
