import { getBucketStore, getConnectedAccountStore } from '../adapters/index.js';
import type { UserBucket } from '../adapters/types.js';
import { DEFAULT_BUCKET_ID } from '../admin/consts.js';
import { grantsIn } from '../end_users/sessions.js';
import { eventBus } from '../event_bus.js';
import {
	connectedAccountKey,
	connectedServiceKey,
	type Grant
} from '../models/grant.js';
import type { PipelineParams } from '../consts/param_list.js';
import type { OIDCContext } from '../helpers/oidc_context.js';
import { findDeclaredResource } from '../resources/registry.js';
import { namespaceOf } from '../resources/namespace.js';
import type { ConnectedAccount, ConnectedService } from './types.js';

/*
 * The person's use consent (specs/118 R7, R8): which of their connected accounts an agent may obtain tokens for.
 * Recorded on the person's grants to the agent, so it goes wherever a grant goes. Asked once on the consent screen,
 * given and withdrawn on the account page; never assumed, not even for an application whose consent is waived.
 */

export interface ConnectedOffer {
	/* `account:<id>` or `service:<id>`, as the grant records the answer. */
	key: string;
	serviceId: string;
	connectedAccountId?: string;
	serviceName: string;
	/* The account's label; absent while the person has no account at the service. */
	label?: string;
}

/*
 * The services an application's access could use: those whose allow-list names it, and those naming the
 * application an administrator linked to an API it asks for.
 */
export async function servicesFor(
	bucket: UserBucket,
	clientId: string,
	resources: readonly string[]
): Promise<ConnectedService[]> {
	const exchangers = new Set([clientId]);
	for (const identifier of resources) {
		const declared = await findDeclaredResource(
			identifier,
			namespaceOf(bucket)
		);
		if (declared?.bucketId === bucket._id && declared.exchangedBy) {
			exchangers.add(declared.exchangedBy);
		}
	}
	return (bucket.connectedServices ?? []).filter((service) =>
		(service.applications ?? []).some((app) => exchangers.has(app))
	);
}

/* One offer per account the person has at each service, or one for the service while they have none. */
export async function offersFor(
	bucket: UserBucket,
	accountId: string,
	services: ConnectedService[]
): Promise<ConnectedOffer[]> {
	if (services.length === 0) return [];
	const accounts = await getConnectedAccountStore().listByAccount(
		bucket._id,
		accountId
	);
	const offers: ConnectedOffer[] = [];
	for (const service of services) {
		const mine = accounts.filter((account) => account.serviceId === service.id);
		if (mine.length === 0) {
			offers.push({
				key: connectedServiceKey(service.id),
				serviceId: service.id,
				serviceName: service.displayName
			});
			continue;
		}
		for (const account of mine) {
			offers.push({
				key: connectedAccountKey(account._id),
				serviceId: service.id,
				connectedAccountId: account._id,
				serviceName: service.displayName,
				label: account.label
			});
		}
	}
	return offers;
}

/*
 * What the consent screen still has to ask (specs/118 R8): offers the grant holds no answer for. A refusal counts as
 * an answer except while the application asks again with prompt=consent, as for every other refusal (specs/093).
 */
export async function pendingOffers(
	oidc: OIDCContext<PipelineParams>,
	refusalsCountAsAnswered: boolean
): Promise<ConnectedOffer[]> {
	const accountId =
		oidc.entities.Account?.accountId ?? oidc.session.payload.accountId;
	if (!accountId) return [];
	const bucket = await getBucketStore().find(
		oidc.client.bucketId ?? DEFAULT_BUCKET_ID
	);
	if (!bucket?.connectedServices?.length) return [];
	const services = await servicesFor(
		bucket,
		oidc.client.clientId,
		Object.keys(oidc.resourceServers)
	);
	const grant = oidc.entities.Grant;
	return (await offersFor(bucket, accountId, services)).filter((offer) => {
		const answer = grant?.connectedConsent(offer.key);
		return (
			answer === undefined ||
			(answer === 'declined' && !refusalsCountAsAnswered)
		);
	});
}

/* The consent screen's answer (specs/118 R8): ticked offers allowed, the rest declined, on the grant being saved. */
export function recordAnswers(
	grant: Grant,
	offers: readonly ConnectedOffer[],
	ticked: ReadonlySet<string>
): void {
	const accountId = grant.payload.accountId;
	for (const offer of offers) {
		const allowed = ticked.has(offer.key);
		if (allowed) grant.allowConnected(offer.key);
		else grant.declineConnected(offer.key);
		if (!accountId) continue;
		eventBus.emit('connected_account.consent', {
			bucketId: grant.payload.bucketId ?? DEFAULT_BUCKET_ID,
			serviceId: offer.serviceId,
			connectedAccountId: offer.connectedAccountId ?? '',
			accountId,
			clientId: grant.payload.clientId,
			change: allowed ? 'allowed' : 'declined',
			via: 'consent_screen'
		});
	}
}

function eventOf(record: ConnectedAccount) {
	return {
		bucketId: record.bucketId,
		serviceId: record.serviceId,
		connectedAccountId: record._id,
		accountId: record.accountId
	};
}

/* The person's grants to `clientId`, which every give and withdraw writes alike. */
async function grantsTo(
	bucket: UserBucket,
	accountId: string,
	clientId: string
): Promise<Grant[]> {
	return (await grantsIn(bucket._id, accountId)).filter(
		(grant) => grant.payload.clientId === clientId
	);
}

/*
 * The account page's "Allow" and "Withdraw" (FR-022, FR-022a). Answers false when the person has no grant with the
 * application, which the page refuses as unknown; a withdrawal of something already gone still answers true.
 */
export async function changeConsent(input: {
	bucket: UserBucket;
	record: ConnectedAccount;
	clientId: string;
	change: 'allowed' | 'withdrawn';
}): Promise<boolean> {
	const grants = await grantsTo(
		input.bucket,
		input.record.accountId,
		input.clientId
	);
	if (grants.length === 0) return false;
	const key = connectedAccountKey(input.record._id);
	for (const grant of grants) {
		if (input.change === 'allowed') grant.allowConnected(key);
		else grant.withdrawConnected(key);
		await grant.save();
	}
	eventBus.emit('connected_account.consent', {
		...eventOf(input.record),
		clientId: input.clientId,
		change: input.change,
		via: 'account_page'
	});
	return true;
}

/*
 * A person who answered about a service before having an account there (FR-020): the first account they connect
 * takes that answer, and no later one does.
 */
export async function adoptFirstAccount(
	bucket: UserBucket,
	record: ConnectedAccount
): Promise<void> {
	const serviceKey = connectedServiceKey(record.serviceId);
	const accountKey = connectedAccountKey(record._id);
	for (const grant of await grantsIn(bucket._id, record.accountId)) {
		const answer = grant.connectedConsent(serviceKey);
		if (answer === undefined) continue;
		grant.withdrawConnected(serviceKey);
		if (answer === 'allowed') grant.allowConnected(accountKey);
		else grant.declineConnected(accountKey);
		await grant.save();
	}
}

/* Every agent each of the person's accounts may be used by, with when it last was. */
export async function agentsByAccount(
	bucket: UserBucket,
	accountId: string,
	records: ConnectedAccount[]
): Promise<Map<string, { clientId: string; lastUsedAt?: number }[]>> {
	const grants = await grantsIn(bucket._id, accountId);
	const result = new Map<string, { clientId: string; lastUsedAt?: number }[]>();
	for (const record of records) {
		const key = connectedAccountKey(record._id);
		const clients = [
			...new Set(
				grants
					.filter((grant) => grant.connectedConsent(key) === 'allowed')
					.map((grant) => grant.payload.clientId)
			)
		];
		result.set(
			record._id,
			clients.map((clientId) => {
				const used = record.usedBy?.find(
					(use) => use.clientId === clientId
				)?.at;
				return {
					clientId,
					...(used === undefined ? {} : { lastUsedAt: used })
				};
			})
		);
	}
	return result;
}
