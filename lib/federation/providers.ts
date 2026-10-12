import { ApplicationConfig } from '../configs/application.js';
import type { UserBucket } from '../adapters/types.js';
import type { FederationProvider } from './types.js';
import { offeredProviders } from './offered.js';

export function federationEnabled(): boolean {
	return ApplicationConfig['federation.enabled'];
}

/* Which providers a bucket offers on this instance now: the rule is `offeredProviders`, with the live switch. */
export function enabledProviders(
	bucket: Pick<UserBucket, 'federation'> | null | undefined
): FederationProvider[] {
	return offeredProviders(bucket, federationEnabled());
}

/*
 * Resolved fresh on every hop, never carried in the round-trip record: a provider deleted, disabled or
 * re-issued while a user was away at the upstream must not be completed against stale settings.
 *
 * Returns undefined for "unknown, disabled, or not in this bucket" without distinguishing them — a probe
 * must not learn which providers a bucket holds.
 */
export function findEnabledProvider(
	bucket: Pick<UserBucket, 'federation'> | null | undefined,
	providerId: string
): FederationProvider | undefined {
	return enabledProviders(bucket).find(
		(provider) => provider.id === providerId
	);
}
