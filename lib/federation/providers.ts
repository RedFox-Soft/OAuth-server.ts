import { ApplicationConfig } from '../configs/application.js';
import type { UserBucket } from '../adapters/types.js';
import type { FederationProvider } from './types.js';

/*
 * Which providers a bucket actually offers.
 *
 * Availability is *derived* here and nowhere else — `federation.some(p => p.enabled)` — so a provider is
 * enabled in exactly one place. A second field claiming the same fact is the shape that disagrees after the
 * first edit, which is why `authMethods` was deleted rather than repurposed.
 *
 * The deployment switch is folded in at this level rather than checked per call site: with federation off,
 * a bucket offers nothing whatever it holds, and the login page and the routes both ask the same question.
 */

export function federationEnabled(): boolean {
	return ApplicationConfig['federation.enabled'] === true;
}

export function enabledProviders(
	bucket: Pick<UserBucket, 'federation'> | null | undefined
): FederationProvider[] {
	if (!federationEnabled() || !bucket) return [];
	return (bucket.federation ?? []).filter((provider) => provider.enabled);
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
