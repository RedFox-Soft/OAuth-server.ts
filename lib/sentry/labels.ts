import { ISSUER } from '../configs/env.js';
import { packageVersion } from '../helpers/package_version.js';

/*
 * The three labels every event carries, derived rather than typed in.
 *
 * These were operator-entered settings and should not have been. A release label maintained by hand
 * goes stale the first time someone deploys without editing it, and a stale label is worse than none:
 * it sends an investigation to a build that never ran. The same applies to the environment — a
 * deployment already knows which one it is, and asking it to also be told is asking for the two to
 * disagree.
 *
 * Deliberately introduces no new environment variable. Everything here comes from what the deployment
 * already declares: NODE_ENV, the package manifest, and ISSUER. A knob invented for this feature
 * would be one more thing to set correctly, and one more way for an event to misreport its origin.
 *
 * Cached: none of these can change without a restart, and a restart re-reads them.
 */
interface Labels {
	environment: string;
	instance: string;
	release?: string;
}

let cached: Labels | undefined;

export function eventLabels(): Labels {
	if (cached) {
		return cached;
	}

	/*
	 * Absent rather than empty when the manifest carries no version. An empty release is not "no
	 * release" to Sentry, it is a release named "", which files every unlabelled deployment under one
	 * heading.
	 */
	const release = packageVersion();

	cached = {
		environment: process.env.NODE_ENV?.trim() || 'development',
		/*
		 * The issuer, not the hostname. It is already required to be correct per deployment, whereas a
		 * container hostname is usually a random id that tells an operator nothing and changes on every
		 * restart.
		 */
		instance: ISSUER,
		...(release ? { release } : {})
	};
	return cached;
}

/* Test seam: forget the cache so a spec can observe resolution again. */
export function resetLabelsForTest(): void {
	cached = undefined;
}
