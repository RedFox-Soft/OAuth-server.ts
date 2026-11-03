import type { Static } from 'elysia';

import {
	getBucketStore,
	getConnectedAccountStore
} from '../../adapters/index.js';
import type { UserBucket } from '../../adapters/types.js';
import { AdminError } from '../auth/rbac.js';
import { connectCallbackUri } from '../../connected_services/catalogue.js';
import { destroyServiceAccounts } from '../../connected_services/accounts.js';
import type { ConnectedService } from '../../connected_services/types.js';
import {
	CONNECTED_SERVICE_CATALOGUE,
	connectedServiceEntry
} from '../../consts/connected_service_catalogue.js';
import { SECRET_MASK } from '../../federation/consts.js';
import { discover, DiscoveryError } from '../../federation/discovery.js';
import nanoid from '../../helpers/nanoid.js';
import { activeKeyring } from '../../sealing/keyring.js';
import { assertReachable } from '../../shared/egress.js';
import { adapter } from '../../adapters/index.js';
import { whyCannotExchange } from '../../connected_services/eligibility.js';
import {
	linkableSignInProviders,
	signInMatch,
	type SignInMatch
} from '../../connected_services/link_signin.js';
import type { CreateServiceBody, UpdateServiceBody } from './schema.js';

/*
 * Every change to a project's connected services (specs/117), modelled on lib/admin/federation/service.ts. The
 * routes authorize, audit and call these; nothing here decides who may.
 */

type CreateBody = Static<typeof CreateServiceBody>;
type UpdateBody = Static<typeof UpdateServiceBody>;

export interface ServiceView extends Omit<ConnectedService, 'clientSecret'> {
	clientSecret: string;
	/* The linked sign-in provider, and those that could be linked now (specs/120). */
	signInProvider?: { id: string; displayName: string };
	linkableSignInProviders: { id: string; displayName: string }[];
	connectedAccounts: number;
	callbackUri: string;
	/* What an agent names in `audience` to obtain this service's tokens (specs/118 R5). */
	identifier: string;
	applications: string[];
}

/*
 * Each listed application must be able to exchange at all (specs/118 FR-019), refused by name. An application deleted
 * since it was listed is dropped rather than refused, so removing one is never blocked by another that is gone.
 */
async function acceptedApplications(
	bucket: UserBucket,
	applications: string[],
	before: readonly string[]
): Promise<string[]> {
	const accepted: string[] = [];
	for (const clientId of applications) {
		const why = await whyCannotExchange(bucket, clientId);
		if (!why) {
			accepted.push(clientId);
			continue;
		}
		if (before.includes(clientId) && !(await stillExists(clientId))) continue;
		throw new AdminError(400, why, { field: 'applications' });
	}
	return accepted;
}

async function stillExists(clientId: string): Promise<boolean> {
	return (await adapter('Client').find(clientId)) !== undefined;
}

const IMMUTABLE = [
	'kind',
	'catalogueId',
	'issuer',
	'tenant',
	'clientId'
] as const;

export function servicesOf(bucket: UserBucket): ConnectedService[] {
	return bucket.connectedServices ?? [];
}

export function findService(
	bucket: UserBucket,
	serviceId: string
): ConnectedService {
	const service = servicesOf(bucket).find((item) => item.id === serviceId);
	if (!service) throw new AdminError(404, 'connected service not found');
	return service;
}

export async function present(
	bucket: UserBucket,
	service: ConnectedService
): Promise<ServiceView> {
	const applications: string[] = [];
	for (const clientId of service.applications ?? []) {
		if (await stillExists(clientId)) applications.push(clientId);
	}
	return {
		...service,
		identifier: service.id,
		applications,
		// Shown as set even when it cannot be opened: it was written, and the keyring card says which.
		clientSecret: SECRET_MASK,
		connectedAccounts: await getConnectedAccountStore().countByService(
			bucket._id,
			service.id
		),
		callbackUri: connectCallbackUri(bucket),
		...signInView(bucket, service)
	};
}

function signInView(bucket: UserBucket, service: ConnectedService) {
	const linked = service.signInProviderId
		? bucket.federation.find((p) => p.id === service.signInProviderId)
		: undefined;
	return {
		...(linked
			? { signInProvider: { id: linked.id, displayName: linked.displayName } }
			: {}),
		linkableSignInProviders: linkableSignInProviders(bucket, service).map(
			(provider) => ({ id: provider.id, displayName: provider.displayName })
		)
	};
}

const MISMATCH: Record<Exclude<SignInMatch, 'ok' | 'unlinkable'>, string> = {
	provider: 'the sign-in provider is not the same provider as this service',
	client_id:
		'the sign-in provider uses another client id: its tokens could not be refreshed with this service’s registration',
	tenant: 'the sign-in provider admits another Microsoft tenant'
};

/*
 * Whether `providerId` may keep this service's tokens (specs/120 R2), refused with why before anything is written:
 * the same provider and registration, not linked to another service, a keyring in use.
 */
export function assertSignInLink(
	bucket: UserBucket,
	service: ConnectedService,
	providerId: string
): void {
	assertKeyringInUse();
	const provider = bucket.federation.find((entry) => entry.id === providerId);
	if (!provider) {
		throw new AdminError(
			404,
			'no sign-in provider with that id in this project',
			{
				field: 'signInProviderId'
			}
		);
	}
	const match = signInMatch(service, provider);
	if (match === 'unlinkable') {
		throw new AdminError(
			409,
			'this service has no sign-in counterpart: its tokens do not come from a sign-in',
			{ code: 'sign_in_provider_unlinkable' }
		);
	}
	if (match !== 'ok') {
		throw new AdminError(409, MISMATCH[match], {
			code: 'sign_in_provider_mismatch'
		});
	}
	const other = servicesOf(bucket).find(
		(entry) => entry.id !== service.id && entry.signInProviderId === providerId
	);
	if (other) {
		throw new AdminError(
			409,
			`that sign-in provider already keeps tokens for ${other.displayName}`,
			{ code: 'sign_in_provider_taken' }
		);
	}
}

export async function presentAll(bucket: UserBucket) {
	return {
		services: await Promise.all(
			servicesOf(bucket).map((service) => present(bucket, service))
		),
		callbackUri: connectCallbackUri(bucket)
	};
}

export function catalogueView() {
	return {
		entries: CONNECTED_SERVICE_CATALOGUE.map((entry) => ({
			catalogueId: entry.catalogueId,
			displayName: entry.displayName,
			requiredValues: entry.requiredValues,
			defaultScopes: entry.defaultScopes,
			consoleUrl: entry.consoleUrl,
			steps: entry.steps
		}))
	};
}

/* FR-005: nothing is declared or edited while there is no keyring to seal its secret or its accounts' tokens. */
export function assertKeyringInUse(): void {
	if (!activeKeyring()) {
		throw new AdminError(
			409,
			'Stored secrets are not encrypted on this instance. Add a keyring (Keys page) before declaring a connected service.',
			{ code: 'keyring_required' }
		);
	}
}

/*
 * FR-007: https, and an address this server may talk to, checked before anything is stored, so a declaration can
 * never point the token request, carrying the client secret, at the instance's own network.
 */
async function assertEndpoint(field: string, value: string): Promise<void> {
	const url = URL.parse(value);
	if (url?.protocol !== 'https:') {
		throw new AdminError(400, `${field} must be an https URL`, { field });
	}
	if (await assertReachable(url.hostname)) {
		throw new AdminError(
			400,
			`${field} is not an address this server may reach`,
			{
				field
			}
		);
	}
}

async function assertDiscoverable(
	field: string,
	issuer: string
): Promise<void> {
	await assertEndpoint(field, issuer);
	try {
		await discover(issuer);
	} catch (err) {
		if (err instanceof DiscoveryError) {
			throw new AdminError(400, `${field}: discovery failed (${err.reason})`, {
				field
			});
		}
		throw err;
	}
}

async function assertGenericEndpoints(
	values: Partial<
		Pick<
			ConnectedService,
			| 'authorizationEndpoint'
			| 'tokenEndpoint'
			| 'revocationEndpoint'
			| 'identity'
		>
	>
): Promise<void> {
	for (const field of [
		'authorizationEndpoint',
		'tokenEndpoint',
		'revocationEndpoint'
	] as const) {
		const value = values[field];
		if (value !== undefined) await assertEndpoint(field, value);
	}
	if (values.identity?.source === 'endpoint') {
		await assertEndpoint('identity.url', values.identity.url);
	}
}

export async function createService(
	bucket: UserBucket,
	body: CreateBody
): Promise<ConnectedService> {
	if (body.clientSecret === SECRET_MASK) {
		throw new AdminError(400, 'clientSecret must be the secret itself', {
			field: 'clientSecret'
		});
	}
	const now = new Date().toISOString();
	const required = <T>(value: T | undefined, field: string): T => {
		if (value === undefined) {
			throw new AdminError(
				400,
				`${field} is required for a ${body.kind} service`,
				{
					field
				}
			);
		}
		return value;
	};
	let service: ConnectedService;
	if (body.kind === 'catalogue') {
		const entry = connectedServiceEntry(
			required(body.catalogueId, 'catalogueId')
		);
		if (!entry) throw new AdminError(400, 'unknown catalogue entry');
		const takesTenant = entry.requiredValues.some(
			(value) => value.name === 'tenant'
		);
		if (takesTenant && !body.tenant) {
			throw new AdminError(400, 'tenant is required for Microsoft', {
				field: 'tenant'
			});
		}
		service = {
			id: nanoid(),
			kind: 'catalogue',
			catalogueId: entry.catalogueId,
			...(takesTenant && body.tenant ? { tenant: body.tenant } : {}),
			clientId: body.clientId,
			clientSecret: body.clientSecret,
			scopes: body.scopes ?? [...entry.defaultScopes],
			displayName: body.displayName ?? entry.displayName,
			createdAt: now,
			updatedAt: now
		};
	} else if (body.kind === 'oidc') {
		const issuer = required(body.issuer, 'issuer');
		const displayName = required(body.displayName, 'displayName');
		await assertDiscoverable('issuer', issuer);
		service = {
			id: nanoid(),
			kind: 'oidc',
			issuer,
			clientId: body.clientId,
			clientSecret: body.clientSecret,
			scopes: body.scopes ?? [],
			displayName,
			createdAt: now,
			updatedAt: now
		};
	} else {
		const authorizationEndpoint = required(
			body.authorizationEndpoint,
			'authorizationEndpoint'
		);
		const tokenEndpoint = required(body.tokenEndpoint, 'tokenEndpoint');
		const identity = required(body.identity, 'identity');
		const displayName = required(body.displayName, 'displayName');
		await assertGenericEndpoints({
			authorizationEndpoint,
			tokenEndpoint,
			identity,
			...(body.revocationEndpoint
				? { revocationEndpoint: body.revocationEndpoint }
				: {})
		});
		service = {
			id: nanoid(),
			kind: 'oauth2',
			authorizationEndpoint,
			tokenEndpoint,
			identity,
			...(body.revocationEndpoint
				? { revocationEndpoint: body.revocationEndpoint }
				: {}),
			clientId: body.clientId,
			clientSecret: body.clientSecret,
			scopes: body.scopes ?? [],
			displayName,
			createdAt: now,
			updatedAt: now
		};
	}
	if (body.applications !== undefined) {
		service.applications = await acceptedApplications(
			bucket,
			body.applications,
			[]
		);
	}
	if (body.signInProviderId !== undefined) {
		assertSignInLink(bucket, service, body.signInProviderId);
		service.signInProviderId = body.signInProviderId;
	}
	await getBucketStore().update(bucket._id, {
		connectedServices: [...servicesOf(bucket), service]
	});
	return service;
}

export async function updateService(
	bucket: UserBucket,
	serviceId: string,
	body: UpdateBody
): Promise<ConnectedService> {
	const current = findService(bucket, serviceId);
	for (const field of IMMUTABLE) {
		if (body[field] !== undefined) {
			throw new AdminError(
				400,
				`${field} cannot change: the tokens of every connected account belong to this registration. Declare a new service instead.`,
				{ field }
			);
		}
	}
	const generic = {
		...(body.authorizationEndpoint !== undefined
			? { authorizationEndpoint: body.authorizationEndpoint }
			: {}),
		...(body.tokenEndpoint !== undefined
			? { tokenEndpoint: body.tokenEndpoint }
			: {}),
		...(body.revocationEndpoint !== undefined
			? { revocationEndpoint: body.revocationEndpoint }
			: {}),
		...(body.identity !== undefined ? { identity: body.identity } : {})
	};
	if (Object.keys(generic).length > 0 && current.kind !== 'oauth2') {
		throw new AdminError(
			400,
			'endpoints are set only on a plain OAuth 2.0 service'
		);
	}
	await assertGenericEndpoints(generic);
	if (typeof body.signInProviderId === 'string') {
		assertSignInLink(bucket, current, body.signInProviderId);
	}
	const { signInProviderId: wasLinked, ...unlinked } = current;
	const linked =
		body.signInProviderId === undefined ? wasLinked : body.signInProviderId;
	const applications =
		body.applications === undefined
			? undefined
			: await acceptedApplications(
					bucket,
					body.applications,
					current.applications ?? []
				);
	const next: ConnectedService = {
		...unlinked,
		...(linked ? { signInProviderId: linked } : {}),
		...generic,
		...(applications === undefined ? {} : { applications }),
		...(body.scopes !== undefined ? { scopes: body.scopes } : {}),
		...(body.displayName !== undefined
			? { displayName: body.displayName }
			: {}),
		// The mask, or nothing, means "unchanged": a console form loads the mask and sends it back.
		...(body.clientSecret !== undefined && body.clientSecret !== SECRET_MASK
			? { clientSecret: body.clientSecret }
			: {}),
		updatedAt: new Date().toISOString()
	};
	await getBucketStore().update(bucket._id, {
		connectedServices: servicesOf(bucket).map((service) =>
			service.id === serviceId ? next : service
		)
	});
	return next;
}

/*
 * The accounts first, while the service is still on the record their revocations read; then the service. A failure
 * between the two leaves a service with no accounts, which the next delete finishes.
 */
export async function deleteService(
	bucket: UserBucket,
	serviceId: string
): Promise<number> {
	findService(bucket, serviceId);
	const disconnected = await destroyServiceAccounts(bucket, serviceId);
	await getBucketStore().update(bucket._id, {
		connectedServices: servicesOf(bucket).filter(
			(service) => service.id !== serviceId
		)
	});
	return disconnected;
}
