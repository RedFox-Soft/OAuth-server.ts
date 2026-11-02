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
import { text } from '../i18n/message.js';
import { emailLanguage } from '../i18n/resolve.js';
import { ACCOUNT_TEXTS } from '../i18n/texts/account/index.js';
import { sanitiseClientName } from '../interactions/clientName.js';
import { Client } from '../models/client.js';
import { connectedAccountKey } from '../models/grant.js';
import { activeKeyring } from '../sealing/keyring.js';
import type { User } from '../adapters/types.js';
import { serviceOf, statusOf } from './accounts.js';
import { issueLink } from './link.js';
import { freshAccount } from './refresh.js';
import { exchangeSubject } from './subject.js';
import type {
	ConnectedAccount,
	ConnectedService,
	ConnectLinkAct
} from './types.js';

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
				`the person has not allowed this application to use that ${serviceName} account`,
				{ target: named._id }
			);
		}
		return named;
	}
	if (allowed.length === 1) return allowed[0];
	if (allowed.length > 1) {
		/* Only the accounts this agent may use: it would receive each of their tokens anyway (specs/119 FR-013). */
		throw new UpstreamTokenRefused(
			'account_selection_required',
			`the person allowed more than one ${serviceName} account: name one with login_hint`,
			{ accounts: allowed.map((account) => account.label).sort() }
		);
	}
	if (accounts.length > 0) {
		throw new UpstreamTokenRefused(
			'consent_required',
			`the person has not allowed this application to use their ${serviceName} account`,
			accounts.length === 1 ? { target: accounts[0]._id } : {}
		);
	}
	throw new UpstreamTokenRefused(
		'connect_required',
		`the person has not connected a ${serviceName} account`
	);
}

/*
 * A scope the service does not declare cannot be had by reconnecting, which asks the provider for the declared ones
 * only: that is the administrator's to add (specs/119 R2). A declared one the account lacks is the person's.
 */
function assertScopes(
	record: ConnectedAccount,
	asked: string[],
	service: ConnectedService
): void {
	const declared = new Set(service.scopes);
	const undeclared = asked.filter((scope) => !declared.has(scope));
	if (undeclared.length > 0) {
		throw new UpstreamTokenRefused(
			'not_permitted',
			`the service does not declare ${undeclared.join(' ')}: an administrator must add it`,
			{ scope: true }
		);
	}
	const held = new Set(record.scopes);
	const missing = asked.filter((scope) => !held.has(scope));
	if (missing.length > 0) {
		throw new UpstreamTokenRefused(
			'reconnect_required',
			`the account lacks ${missing.join(' ')}: the person must reconnect it to grant more`,
			{ target: record._id }
		);
	}
}

const MESSAGE = {
	connect: 'linkMessageConnect',
	consent: 'linkMessageConsent',
	reconnect: 'linkMessageReconnect'
} as const;

function actOf(refusal: UpstreamTokenRefused): ConnectLinkAct | undefined {
	switch (refusal.reason) {
		case 'connect_required':
			return 'connect';
		case 'consent_required':
			return 'consent';
		case 'reconnect_required':
			return 'reconnect';
		default:
			return undefined;
	}
}

async function agentName(clientId: string): Promise<string> {
	const client = await Client.tryFind(clientId);
	return (client && sanitiseClientName(client.clientName)) ?? clientId;
}

/*
 * The person's link, on a refusal only they can fix (specs/119 R2). A link that cannot be made leaves the refusal
 * as it was: the agent still learns why, as it did before links existed.
 */
async function attachLink(
	refusal: UpstreamTokenRefused,
	at: {
		bucket: UserBucket;
		user: User;
		service: ConnectedService;
		agent: string;
		exchangedBy: string;
	}
): Promise<void> {
	const act = actOf(refusal);
	if (!act) return;
	try {
		const issued = await issueLink({
			bucket: at.bucket,
			accountId: at.user._id,
			clientId: at.agent,
			exchangedBy: at.exchangedBy,
			serviceId: at.service.id,
			act,
			...(refusal.target ? { connectedAccountId: refusal.target } : {})
		});
		const T = ACCOUNT_TEXTS[emailLanguage(at.user)];
		refusal.link = {
			uri: issued.uri,
			ref: issued.ref,
			expiresIn: issued.expiresIn,
			message: text(T[MESSAGE[act]], {
				service: at.service.displayName,
				app: await agentName(at.agent)
			})
		};
	} catch (error) {
		console.error('connected services: a connect link could not be made', {
			serviceId: at.service.id,
			error
		});
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

	try {
		return await upstreamToken(
			bucket,
			service,
			subject,
			params,
			client.clientId
		);
	} catch (err) {
		if (err instanceof UpstreamTokenRefused) {
			await attachLink(err, {
				bucket,
				user,
				service,
				agent: subject.agentClientId,
				exchangedBy: client.clientId
			});
		}
		throw err;
	}
}

/* The checks past the administrator's list: the person's accounts, their consent, the account itself. */
async function upstreamToken(
	bucket: UserBucket,
	service: ConnectedService,
	subject: Awaited<ReturnType<typeof exchangeSubject>>,
	params: TokenParams,
	exchangedBy: string
) {
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
			`the person must reconnect their ${service.displayName} account`,
			{ target: chosen._id }
		);
	}
	const asked = params.scope?.split(' ').filter(Boolean) ?? [];
	assertScopes(chosen, asked, service);

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
			`the person must reconnect their ${service.displayName} account`,
			{ target: chosen._id }
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
			`the person must reconnect their ${service.displayName} account`,
			{ target: record._id }
		);
	}
	assertScopes(record, asked, service);

	noteUse(record, subject.agentClientId);
	eventBus.emit('connected_account.exchanged', {
		bucketId: record.bucketId,
		serviceId: record.serviceId,
		connectedAccountId: record._id,
		accountId: record.accountId,
		clientId: subject.agentClientId,
		exchangedBy
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
