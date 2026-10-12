import type { UserBucket } from '../adapters/types.js';
import type { FederationProvider } from './types.js';

/*
 * Which providers a bucket actually offers, given whether federation is on at all.
 *
 * Availability is *derived* here and nowhere else — `federation.some(p => p.enabled)` — so a provider is
 * enabled in exactly one place. A second field claiming the same fact is the shape that disagrees after the
 * first edit, which is why `authMethods` was deleted rather than repurposed.
 *
 * The deployment switch is an argument rather than read here, so this module imports nothing that reaches the
 * configuration: the console's preview of a sign-in page (specs/091) asks the same question in a browser, with
 * the switch the server reported. The server asks through `enabledProviders`, which supplies the live value.
 */
export function offeredProviders(
	bucket: Pick<UserBucket, 'federation'> | null | undefined,
	federationOn: boolean
): FederationProvider[] {
	if (!federationOn || !bucket) return [];
	return bucket.federation.filter((provider) => provider.enabled);
}
