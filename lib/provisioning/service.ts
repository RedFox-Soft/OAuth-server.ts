import { nanoid } from 'nanoid';

import {
	getBucketStore,
	getProvisioningConnectionStore,
	getProvisioningRefusalStore,
	getUserStore
} from '../adapters/index.js';
import type {
	ConnectionCorrelation,
	DeprovisioningThreshold,
	KeyCredential,
	ProvisioningConnection,
	ProvisioningConnectionPatch,
	RefusedOperation,
	UserBucket
} from '../adapters/types.js';
import { isUniqueValueTaken } from '../adapters/conflicts.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import { ownedGroupCount } from '../bucket_groups/service.js';
import { ApplicationConfig } from '../configs/application.js';
import { cascadeForClient, type CascadeResult } from '../helpers/cascade.js';
import { OIDCProviderError } from '../helpers/errors.js';
import { validateClient } from '../models/client/validate.js';
import { scimBaseUrl, scimMetadataUrl, tokenEndpointFor } from './addresses.js';
import { connectionClientId, connectionClientMetadata } from './client.js';
import { CLAIM_NAME_PATTERN, defaultCorrelationFor } from './correlation.js';
import {
	digestOf,
	newConnectionSecret,
	newStaticToken
} from './credentials.js';

/*
 * Every change to a provisioning connection, whichever surface asks — the admin API, and MCP through it.
 * Like the end-user service, each mutation takes the surface's `record` and calls it after every refusal and
 * before the first write, so a refused change writes no audit entry and no change is written without one.
 */

export type RecordChange = () => Promise<unknown>;

export class ProvisioningError extends Error {
	constructor(
		readonly status: 403 | 404 | 409 | 422,
		message: string,
		readonly extra: Record<string, unknown> = {}
	) {
		super(message);
		this.name = 'ProvisioningError';
	}
}

const store = () => getProvisioningConnectionStore();
const refusals = () => getProvisioningRefusalStore();

export async function loadConnection(
	bucket: UserBucket,
	connectionId: string
): Promise<ProvisioningConnection> {
	const connection = await store().find(connectionId);
	/* Another bucket's connection does not exist as far as this bucket's administrator can tell. */
	if (!connection || connection.bucketId !== bucket._id) {
		throw new ProvisioningError(404, 'provisioning connection not found');
	}
	return connection;
}

export async function managedUserCount(
	bucketId: string,
	connectionId: string
): Promise<number> {
	const { totalResults } = await getUserStore(bucketId).query(
		{ provisionedBy: connectionId },
		{ startIndex: 1, count: 0 }
	);
	return totalResults;
}

function assertCorrelation(correlation: ConnectionCorrelation | undefined) {
	if (correlation && !CLAIM_NAME_PATTERN.test(correlation.claim)) {
		throw new ProvisioningError(
			422,
			'correlation.claim must be a claim name of 1–64 letters, digits, or _ . : -'
		);
	}
}

export interface CreateConnectionInput {
	displayName: string;
	providerId: string;
	correlation?: ConnectionCorrelation;
	emailTrust?: 'trusted' | 'untrusted';
	/* The mass-deprovisioning guard; absent or `null` leaves it off, the default (specs/072 FR-017). */
	threshold?: DeprovisioningThreshold | null;
}

/*
 * Creating a connection also closes its provider to just-in-time creation: with SCIM on, an account the
 * provider's first sign-in created would race the directory's own create of the same person and leave two
 * accounts for one (issue #62). Written in the same act, so the audit entry for the connection covers it.
 */
export async function createConnection(
	bucket: UserBucket,
	input: CreateConnectionInput,
	/* Given the id the connection is about to have, so the entry can name it — audit-first has nothing else. */
	record: (connectionId: string) => Promise<unknown>
): Promise<ProvisioningConnection> {
	if (bucket._id === ADMIN_BUCKET_ID) {
		throw new ProvisioningError(
			403,
			'the administrators’ bucket cannot be provisioned by a directory'
		);
	}
	const provider = bucket.federation.find((p) => p.id === input.providerId);
	if (!provider) {
		throw new ProvisioningError(
			422,
			`provider ${input.providerId} is not configured on this bucket`
		);
	}
	const bound = await store().findByProvider(bucket._id, provider.id);
	if (bound) {
		throw new ProvisioningError(
			409,
			`provider ${provider.id} is already bound to connection ${bound._id}`
		);
	}
	assertCorrelation(input.correlation);

	const connectionId = nanoid();
	await record(connectionId);
	let connection: ProvisioningConnection;
	try {
		connection = await store().create({
			_id: connectionId,
			bucketId: bucket._id,
			displayName: input.displayName,
			enabled: true,
			providerId: provider.id,
			correlation: input.correlation ?? defaultCorrelationFor(provider),
			emailTrust: input.emailTrust ?? 'untrusted',
			oauthCredential: null,
			...(input.threshold ? { threshold: { ...input.threshold } } : {})
		});
	} catch (error) {
		if (isUniqueValueTaken(error)) {
			throw new ProvisioningError(
				409,
				`provider ${provider.id} is already bound to a connection`
			);
		}
		throw error;
	}

	if (provider.provisioning !== 'existing_only') {
		await getBucketStore().update(bucket._id, {
			federation: bucket.federation.map((p) =>
				p.id === provider.id
					? { ...p, provisioning: 'existing_only' as const }
					: p
			)
		});
	}
	return connection;
}

export interface UpdateConnectionInput {
	displayName?: string;
	enabled?: boolean;
	correlation?: ConnectionCorrelation;
	emailTrust?: 'trusted' | 'untrusted';
	/* A threshold sets or changes the guard; `null` removes it; absent leaves it as it is. */
	threshold?: DeprovisioningThreshold | null;
}

function sameThreshold(
	a: DeprovisioningThreshold | undefined,
	b: DeprovisioningThreshold | null
): boolean {
	return (
		(a === undefined && b === null) ||
		(a !== undefined &&
			b !== null &&
			a.count === b.count &&
			a.windowSeconds === b.windowSeconds)
	);
}

/*
 * No field here reaches the hold: `enabled`, a new threshold or any other edit leaves a held connection held,
 * because only an explicit release may end it (FR-023). Removing the threshold is refused while held, so a hold
 * never outlives the guard that set it without an administrator having released it first.
 */
export async function updateConnection(
	bucket: UserBucket,
	connectionId: string,
	input: UpdateConnectionInput,
	record: RecordChange
): Promise<ProvisioningConnection> {
	const connection = await loadConnection(bucket, connectionId);
	assertCorrelation(input.correlation);
	const patch: ProvisioningConnectionPatch = {};
	if (input.displayName !== undefined) patch.displayName = input.displayName;
	if (input.enabled !== undefined) patch.enabled = input.enabled;
	if (input.correlation !== undefined) patch.correlation = input.correlation;
	if (input.emailTrust !== undefined) patch.emailTrust = input.emailTrust;
	if (
		input.threshold !== undefined &&
		!sameThreshold(connection.threshold, input.threshold)
	) {
		if (input.threshold === null && connection.hold) {
			throw new ProvisioningError(
				409,
				'the connection is held; release the hold before removing the guard'
			);
		}
		/* An undefined value removes the field (the stores' patch convention). */
		patch.threshold = input.threshold ?? undefined;
		/*
		 * A changed or removed threshold starts the count afresh (FR-024): the slots taken under the old one
		 * were sized and timed by it, and are left to expire under the old generation's ids.
		 */
		patch.tallyEpoch = (connection.tallyEpoch ?? 0) + 1;
	}

	await record();
	const updated = await store().update(connectionId, patch);
	if (!updated)
		throw new ProvisioningError(404, 'provisioning connection not found');
	return updated;
}

/*
 * Refused while the connection manages anyone or any group (spec 070 FR-007, spec 071 FR-012): deleting
 * people — or the groups relying parties authorize on — must never be a side effect of deleting a piece of
 * configuration, and releasing them to local administration silently would break the directory's claim to
 * be their source of truth. Disabling is the alternative while that is decided.
 */
export async function deleteConnection(
	bucket: UserBucket,
	connectionId: string,
	record: RecordChange
): Promise<CascadeResult> {
	const connection = await loadConnection(bucket, connectionId);
	const managed = await managedUserCount(bucket._id, connection._id);
	const groups = await ownedGroupCount(bucket._id, connection._id);
	if (managed > 0 || groups > 0) {
		const owned = [
			...(managed > 0 ? [`${managed} user${managed === 1 ? '' : 's'}`] : []),
			...(groups > 0 ? [`${groups} group${groups === 1 ? '' : 's'}`] : [])
		].join(' and ');
		throw new ProvisioningError(
			409,
			`connection manages ${owned}; disable it instead, or remove them through the directory first`,
			{
				blockers: [
					...(managed > 0 ? [{ kind: 'enduser', count: managed }] : []),
					...(groups > 0 ? [{ kind: 'bucketgroup', count: groups }] : [])
				]
			}
		);
	}
	await record();
	/* Before the connection, so a failure here leaves it in place for a retry rather than records nothing reads. */
	await refusals().destroyByConnection(connection._id);
	await store().destroy(connection._id);
	return cascadeForClient(connectionClientId(connection._id));
}

export interface IssueCredentialInput {
	kind: 'key' | 'secret' | 'static_token';
	/* Meaningful with `kind: 'key'` only. */
	jwks?: { keys: Record<string, unknown>[] };
	jwksUri?: string;
	signingAlg?: string;
}

export interface IssuedCredential {
	connection: ProvisioningConnection;
	/* Present only in the response to the issue, and nowhere else, ever. */
	secret?: string;
	token?: string;
}

/*
 * A key set is checked now with the validation the token endpoint will apply, so an administrator learns
 * that a key is private, symmetric or malformed when pasting it rather than from a customer's failed
 * "Test connection" days later.
 */
function assertKeyCredentialValid(
	connection: ProvisioningConnection,
	credential: KeyCredential
) {
	if ((credential.jwks === undefined) === (credential.jwksUri === undefined)) {
		throw new ProvisioningError(
			422,
			'a key credential needs exactly one of jwks or jwksUri'
		);
	}
	if (credential.jwksUri !== undefined) {
		let url: URL;
		try {
			url = new URL(credential.jwksUri);
		} catch {
			throw new ProvisioningError(422, 'jwksUri must be an absolute URL');
		}
		if (url.protocol !== 'https:') {
			throw new ProvisioningError(422, 'jwksUri must be an https URL');
		}
	}
	const metadata = connectionClientMetadata({
		...connection,
		oauthCredential: credential
	});
	try {
		if (metadata) validateClient(metadata);
	} catch (error) {
		if (error instanceof OIDCProviderError) {
			throw new ProvisioningError(
				422,
				error.error_description || error.message
			);
		}
		throw error;
	}
}

export async function issueCredential(
	bucket: UserBucket,
	connectionId: string,
	input: IssueCredentialInput,
	record: RecordChange
): Promise<IssuedCredential> {
	const connection = await loadConnection(bucket, connectionId);
	const issuedAt = new Date();
	if (
		input.kind !== 'key' &&
		(input.jwks !== undefined ||
			input.jwksUri !== undefined ||
			input.signingAlg !== undefined)
	) {
		throw new ProvisioningError(
			422,
			'jwks, jwksUri and signingAlg belong to a key credential only'
		);
	}

	if (input.kind === 'key') {
		const credential: KeyCredential = {
			kind: 'key',
			issuedAt,
			...(input.jwks !== undefined ? { jwks: input.jwks } : {}),
			...(input.jwksUri !== undefined ? { jwksUri: input.jwksUri } : {}),
			...(input.signingAlg !== undefined
				? { signingAlg: input.signingAlg }
				: {})
		};
		assertKeyCredentialValid(connection, credential);
		await record();
		const updated = await replaceOauthCredential(connection, credential);
		return { connection: updated };
	}

	if (input.kind === 'secret') {
		if (!ApplicationConfig['scim.secretCredentials']) {
			throw new ProvisioningError(
				409,
				'secret credentials are switched off (scim.secretCredentials)'
			);
		}
		const secret = newConnectionSecret();
		await record();
		const updated = await replaceOauthCredential(connection, {
			kind: 'secret',
			digest: digestOf(secret),
			issuedAt
		});
		return { connection: updated, secret };
	}

	if (!ApplicationConfig['scim.staticTokens']) {
		throw new ProvisioningError(
			409,
			'static tokens are switched off (scim.staticTokens)'
		);
	}
	const token = newStaticToken();
	await record();
	const updated = await store().update(connection._id, {
		staticTokenDigest: digestOf(token),
		staticTokenIssuedAt: issuedAt
	});
	if (!updated)
		throw new ProvisioningError(404, 'provisioning connection not found');
	return { connection: updated, token };
}

/*
 * Written, then every token the previous credential obtained is swept: they are `ClientCredentials` rows
 * owned by the client `scim-<id>`, which the client cascade reaches whether or not a client record exists.
 * In this order so nothing new can be minted with the old credential between the sweep and the write.
 */
async function replaceOauthCredential(
	connection: ProvisioningConnection,
	credential: ProvisioningConnection['oauthCredential']
): Promise<ProvisioningConnection> {
	const updated = await store().update(connection._id, {
		oauthCredential: credential
	});
	if (!updated)
		throw new ProvisioningError(404, 'provisioning connection not found');
	await cascadeForClient(connectionClientId(connection._id));
	return updated;
}

export async function revokeCredential(
	bucket: UserBucket,
	connectionId: string,
	kind: 'oauth' | 'static_token',
	record: RecordChange
): Promise<ProvisioningConnection> {
	const connection = await loadConnection(bucket, connectionId);
	await record();
	if (kind === 'oauth') {
		return replaceOauthCredential(connection, null);
	}
	const updated = await store().update(connection._id, {
		staticTokenDigest: undefined,
		staticTokenIssuedAt: undefined
	});
	if (!updated)
		throw new ProvisioningError(404, 'provisioning connection not found');
	return updated;
}

/*
 * Ends a connection's hold and restarts its count, in one write (FR-023). Refused when the connection is not
 * held, so a release in the trail always ended a hold. The store re-checks the hold in the same write, which is
 * what settles two administrators releasing together: the second is told the connection is not held.
 */
export async function releaseConnection(
	bucket: UserBucket,
	connectionId: string,
	record: (refusedRemovals: number) => Promise<unknown>
): Promise<ProvisioningConnection> {
	const connection = await loadConnection(bucket, connectionId);
	if (!connection.hold) {
		throw new ProvisioningError(409, 'the connection is not held');
	}
	/* Counted before the audit entry, which is written first and states how many refused removals it re-admits. */
	const { total } = await refusals().list(
		connection._id,
		connection.tallyEpoch ?? 0,
		0
	);
	await record(total);
	const released = await store().releaseHold(connection._id);
	if (!released) {
		throw new ProvisioningError(409, 'the connection is not held');
	}
	/*
	 * After the hold is cleared, and as a best effort: the release has happened and must be answered as one.
	 * A record this leaves behind belongs to a generation the release has already moved past, so no read
	 * returns it, and the connection's or bucket's deletion removes it.
	 */
	await refusals()
		.destroyByConnection(connection._id)
		.catch(() => 0);
	return released;
}

/*
 * The removals a held connection has been refused in its current hold, most recent first, with the people
 * they name. At most `HOLD_READ_LIMIT` rows; a person deleted since is skipped, and `total` still counts them.
 */
export const HOLD_READ_LIMIT = 1000;

export interface RefusedRemovalView {
	userId: string;
	email: string | null;
	userName: string | null;
	operation: RefusedOperation;
	firstAt: string;
	lastAt: string;
	attempts: number;
}

export type HoldView =
	| { held: false }
	| {
			held: true;
			since: string;
			count: number;
			refused: RefusedRemovalView[];
			total: number;
	  };

export async function readHold(
	bucket: UserBucket,
	connectionId: string
): Promise<HoldView> {
	const connection = await loadConnection(bucket, connectionId);
	if (!connection.hold) return { held: false };
	const { refusals: found, total } = await refusals().list(
		connection._id,
		connection.tallyEpoch ?? 0,
		HOLD_READ_LIMIT
	);
	const people = new Map(
		(await getUserStore(bucket._id).findMany(found.map((r) => r.userId))).map(
			(user) => [user._id, user]
		)
	);
	const refused: RefusedRemovalView[] = [];
	for (const refusal of found) {
		const person = people.get(refusal.userId);
		if (!person) continue;
		refused.push({
			userId: refusal.userId,
			email: person.email || null,
			userName: person.userName ?? null,
			operation: refusal.operation,
			firstAt: refusal.firstAt.toISOString(),
			lastAt: refusal.lastAt.toISOString(),
			attempts: refusal.attempts
		});
	}
	return {
		held: true,
		since: connection.hold.since.toISOString(),
		count: connection.hold.count,
		refused,
		total
	};
}

/*
 * Revokes every token a bucket's connections obtained, and forgets every removal they were refused; called by
 * the bucket-delete route after the users go.
 */
export async function destroyConnectionsOf(
	bucketId: string
): Promise<CascadeResult[]> {
	await refusals().destroyByBucket(bucketId);
	const ids = await store().destroyByBucket(bucketId);
	return Promise.all(ids.map((id) => cascadeForClient(connectionClientId(id))));
}

export type ConnectionWarning =
	| 'scim_disabled'
	| 'bucket_unaddressed'
	| 'provider_disabled'
	| 'client_credentials_disabled'
	| 'credential_kind_disabled';

/*
 * What an administrator sees: everything they need to configure the directory, and nothing that would
 * let anyone else impersonate it — no digest, ever, for any role.
 */
export interface ConnectionView {
	id: string;
	bucketId: string;
	displayName: string;
	enabled: boolean;
	providerId: string;
	correlation: ConnectionCorrelation;
	emailTrust: 'trusted' | 'untrusted';
	clientId: string;
	scimBaseUrl: string | null;
	tokenEndpoint: string;
	metadataUrl: string | null;
	scope: 'scim';
	oauthCredential:
		| { kind: 'key'; issuedAt: string; jwksUri?: string; keyCount?: number }
		| { kind: 'secret'; issuedAt: string }
		| null;
	staticToken: { issuedAt: string } | null;
	/* The mass-deprovisioning guard, absent when off. The tally's generation is bookkeeping and never shown. */
	threshold?: DeprovisioningThreshold;
	/* Present while held: when it began, and the threshold count that was reached. */
	hold?: { since: string; count: number };
	managedUsers: number;
	/* The groups it keeps: the same count that refuses its deletion. */
	managedGroups: number;
	/*
	 * The credentials this instance would issue it now. A key always; a secret and a static token only while
	 * their switches are on, so a console never offers what the issue route would refuse.
	 */
	availableCredentialKinds: CredentialKind[];
	lastUsedAt: string | null;
	createdAt: string;
	warnings: ConnectionWarning[];
}

export type CredentialKind = IssueCredentialInput['kind'];

export function availableCredentialKinds(): CredentialKind[] {
	return [
		'key',
		...(ApplicationConfig['scim.secretCredentials'] ? ['secret' as const] : []),
		...(ApplicationConfig['scim.staticTokens'] ? ['static_token' as const] : [])
	];
}

export interface ConnectionCounts {
	managedUsers: number;
	managedGroups: number;
}

/* Every read of a connection presents it through this, so the list and the single read never differ. */
export async function viewConnection(
	bucket: UserBucket,
	connection: ProvisioningConnection
): Promise<ConnectionView> {
	const [managedUsers, managedGroups] = await Promise.all([
		managedUserCount(bucket._id, connection._id),
		ownedGroupCount(bucket._id, connection._id)
	]);
	return presentConnection(bucket, connection, {
		managedUsers,
		managedGroups
	});
}

export function presentConnection(
	bucket: UserBucket,
	connection: ProvisioningConnection,
	{ managedUsers, managedGroups }: ConnectionCounts
): ConnectionView {
	const warnings: ConnectionWarning[] = [];
	if (!ApplicationConfig['scim.enabled']) warnings.push('scim_disabled');
	if (scimBaseUrl(bucket) === null) warnings.push('bucket_unaddressed');
	const provider = bucket.federation.find(
		(p) => p.id === connection.providerId
	);
	if (!provider?.enabled || !ApplicationConfig['federation.enabled']) {
		warnings.push('provider_disabled');
	}
	const credential = connection.oauthCredential;
	if (credential && !ApplicationConfig['clientCredentials.enabled']) {
		warnings.push('client_credentials_disabled');
	}
	if (
		(credential?.kind === 'secret' &&
			!ApplicationConfig['scim.secretCredentials']) ||
		(connection.staticTokenDigest !== undefined &&
			!ApplicationConfig['scim.staticTokens'])
	) {
		warnings.push('credential_kind_disabled');
	}

	return {
		id: connection._id,
		bucketId: connection.bucketId,
		displayName: connection.displayName,
		enabled: connection.enabled,
		providerId: connection.providerId,
		correlation: { ...connection.correlation },
		emailTrust: connection.emailTrust,
		clientId: connectionClientId(connection._id),
		scimBaseUrl: scimBaseUrl(bucket),
		tokenEndpoint: tokenEndpointFor(bucket),
		metadataUrl: scimMetadataUrl(bucket),
		scope: 'scim',
		oauthCredential: !credential
			? null
			: credential.kind === 'secret'
				? { kind: 'secret', issuedAt: credential.issuedAt.toISOString() }
				: {
						kind: 'key',
						issuedAt: credential.issuedAt.toISOString(),
						...(credential.jwksUri ? { jwksUri: credential.jwksUri } : {}),
						...(credential.jwks
							? { keyCount: credential.jwks.keys.length }
							: {})
					},
		staticToken: connection.staticTokenIssuedAt
			? { issuedAt: connection.staticTokenIssuedAt.toISOString() }
			: null,
		...(connection.threshold ? { threshold: { ...connection.threshold } } : {}),
		...(connection.hold
			? {
					hold: {
						since: connection.hold.since.toISOString(),
						count: connection.hold.count
					}
				}
			: {}),
		managedUsers,
		managedGroups,
		availableCredentialKinds: availableCredentialKinds(),
		lastUsedAt: connection.lastUsedAt?.toISOString() ?? null,
		createdAt: connection.createdAt.toISOString(),
		warnings
	};
}
