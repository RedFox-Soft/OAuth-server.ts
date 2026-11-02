import type { TokenParams } from '../actions/token.js';
import {
	getBucketStore,
	getConnectedAccountStore,
	getUserStore
} from '../adapters/index.js';
import type { UserBucket } from '../adapters/types.js';
import { whyCannotExchange } from './eligibility.js';
import { ACCESS_TOKEN_TYPE } from '../consts/assertion_grants.js';
import { canSignIn } from '../end_users/can_sign_in.js';
import { eventBus } from '../event_bus.js';
import epochTime from '../helpers/epoch_time.js';
import {
	InvalidGrant,
	InvalidRequest,
	InvalidTarget,
	UnauthorizedClient,
	UpstreamTokenRefused
} from '../helpers/errors.js';
import type { OIDCContext } from '../helpers/oidc_context.js';
import type { DPoPProof } from '../helpers/validate_dpop.js';
import { connectedAccountKey } from '../models/grant.js';
import { activeKeyring } from '../sealing/keyring.js';
import { serviceOf, statusOf } from './accounts.js';
import { freshAccount } from './refresh.js';
import { exchangeSubject } from './subject.js';
import type { ConnectedAccount } from './types.js';

/*
 * An agent obtains a person's upstream access token at one of the project's connected services (specs/118,
 * contracts/token-exchange.md). Every check runs on every exchange, in the contract's order: the application, the
 * subject token, the person and the project, the administrator's allow-list, the person's use consent, the account
 * itself. The upstream refresh token never leaves; the access token leaves only in this answer.
 */

/* How often one process writes "last used" for one (account, agent): the page says "about N minutes ago". */
const USE_NOTED_EVERY_SECONDS = 600;
const noted = new Map<string, number>();

function noteUse(record: ConnectedAccount, clientId: string): void {
	const at = epochTime();
	const key = `${record._id}\u0000${clientId}`;
	if ((noted.get(key) ?? 0) + USE_NOTED_EVERY_SECONDS > at) return;
	noted.set(key, at);
	void getConnectedAccountStore()
		.noteUse(record.bucketId, record._id, clientId, at)
		.catch((error: unknown) => {
			noted.delete(key);
			console.error('connected services: last use could not be recorded', {
				connectedAccountId: record._id,
				error
			});
		});
}

function single(
	value: string | string[] | undefined,
	what: string
): string | undefined {
	if (value === undefined) return undefined;
	const values = Array.isArray(value) ? value : [value];
	if (values.length !== 1 || !values[0]) {
		throw new InvalidTarget(`exactly one ${what} names the connected service`);
	}
	return values[0];
}

/* An upstream credential goes only to an application that may ever hold one (specs/118 FR-003). */
async function assertExchangingApplication(
	oidc: OIDCContext<TokenParams>,
	bucket: UserBucket
): Promise<void> {
	const why = await whyCannotExchange(bucket, oidc.client.clientId);
	if (why) throw new UnauthorizedClient(why);
}

function chooseAccount(
	accounts: ConnectedAccount[],
	allowed: ConnectedAccount[],
	loginHint: string | undefined,
	serviceName: string
): ConnectedAccount {
	if (loginHint !== undefined) {
		const named = accounts.find((account) => account.label === loginHint);
		if (!named) {
			throw new UpstreamTokenRefused(
				'connect_required',
				`the person has no ${serviceName} account by that name connected`
			);
		}
		if (!allowed.includes(named)) {
			throw new UpstreamTokenRefused(
				'consent_required',
				`the person has not allowed this application to use that ${serviceName} account`
			);
		}
		return named;
	}
	if (allowed.length === 1) return allowed[0];
	if (allowed.length > 1) {
		throw new UpstreamTokenRefused(
			'account_selection_required',
			`the person allowed more than one ${serviceName} account: name one with login_hint`
		);
	}
	if (accounts.length > 0) {
		throw new UpstreamTokenRefused(
			'consent_required',
			`the person has not allowed this application to use their ${serviceName} account`
		);
	}
	throw new UpstreamTokenRefused(
		'connect_required',
		`the person has not connected a ${serviceName} account`
	);
}

function assertScopes(record: ConnectedAccount, asked: string[]): void {
	const held = new Set(record.scopes);
	const missing = asked.filter((scope) => !held.has(scope));
	if (missing.length > 0) {
		throw new UpstreamTokenRefused(
			'reconnect_required',
			`the account lacks ${missing.join(' ')}: the person must reconnect it to grant more`
		);
	}
}

export async function upstreamExchange(
	oidc: OIDCContext<TokenParams>,
	dPoP: DPoPProof
) {
	const { client, params } = oidc;
	if (
		params.actor_token !== undefined ||
		params.actor_token_type !== undefined
	) {
		throw new InvalidRequest('actor_token is not supported');
	}
	if (params.resource !== undefined) {
		throw new InvalidTarget(
			'name the connected service in audience, not resource'
		);
	}
	const serviceId = single(params.audience, 'audience');
	if (!serviceId) {
		throw new InvalidRequest('audience must name the connected service');
	}

	const bucket = await getBucketStore().find(oidc.bucket._id);
	if (!bucket) throw new InvalidGrant('project');
	await assertExchangingApplication(oidc, bucket);
	const subject = await exchangeSubject(oidc, bucket, dPoP);

	const user = await getUserStore(bucket._id).find(subject.accountId);
	if (!user || !canSignIn(user) || bucket.deletion !== undefined) {
		throw new InvalidGrant('person');
	}

	const service = serviceOf(bucket, serviceId);
	if (!service || !(service.applications ?? []).includes(client.clientId)) {
		throw new UpstreamTokenRefused(
			'not_permitted',
			'this application may not obtain tokens for that connected service'
		);
	}
	if (!activeKeyring()) {
		throw new UpstreamTokenRefused(
			'temporarily_unavailable',
			'connected accounts cannot be read at the moment'
		);
	}

	const accounts = (
		await getConnectedAccountStore().listByAccount(
			bucket._id,
			subject.accountId
		)
	).filter((account) => account.serviceId === service.id);
	const allowed = accounts.filter((account) =>
		subject.grants.some(
			(grant) =>
				grant.connectedConsent(connectedAccountKey(account._id)) === 'allowed'
		)
	);
	const chosen = chooseAccount(
		accounts,
		allowed,
		params.login_hint,
		service.displayName
	);
	if (statusOf(chosen) === 'needs_reconnection') {
		throw new UpstreamTokenRefused(
			'reconnect_required',
			`the person must reconnect their ${service.displayName} account`
		);
	}
	const asked = params.scope?.split(' ').filter(Boolean) ?? [];
	assertScopes(chosen, asked);

	const fresh = await freshAccount(bucket, service, chosen, 'exchange');
	if (fresh.kind === 'gone') {
		throw new UpstreamTokenRefused(
			'connect_required',
			`the person has not connected a ${service.displayName} account`
		);
	}
	if (fresh.kind === 'broken') {
		throw new UpstreamTokenRefused(
			'reconnect_required',
			`the person must reconnect their ${service.displayName} account`
		);
	}
	if (fresh.kind === 'unavailable') {
		throw new UpstreamTokenRefused(
			'temporarily_unavailable',
			`${service.displayName} could not be reached: try again later`
		);
	}
	const { record } = fresh;
	const accessToken = record.accessToken;
	if (!accessToken) {
		throw new UpstreamTokenRefused(
			'reconnect_required',
			`the person must reconnect their ${service.displayName} account`
		);
	}
	assertScopes(record, asked);

	noteUse(record, subject.agentClientId);
	eventBus.emit('connected_account.exchanged', {
		bucketId: record.bucketId,
		serviceId: record.serviceId,
		connectedAccountId: record._id,
		accountId: record.accountId,
		clientId: subject.agentClientId,
		exchangedBy: client.clientId
	});

	const expiresIn =
		record.accessTokenExpiresAt === undefined
			? undefined
			: Math.max(record.accessTokenExpiresAt - epochTime(), 0);
	return {
		access_token: accessToken,
		issued_token_type: ACCESS_TOKEN_TYPE,
		/* How the token is presented at the provider; Slack's own `user` names whose it is, not how. */
		token_type: 'Bearer',
		...(expiresIn === undefined ? {} : { expires_in: expiresIn }),
		...(record.scopes.length > 0 ? { scope: record.scopes.join(' ') } : {})
	};
}
