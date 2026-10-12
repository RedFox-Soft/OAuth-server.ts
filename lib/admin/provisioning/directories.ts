import type { UserBucket } from '../../adapters/types.js';
import {
	KNOWN_DIRECTORIES,
	type DirectoryCredentialKind,
	type DirectoryLabels,
	type KnownDirectoryKey
} from '../../consts/known_directories.js';
import { scimBaseUrl, tokenEndpointFor } from '../../provisioning/addresses.js';

/*
 * The known directories' guidance with this bucket's own values filled in: the SCIM base URL and token
 * endpoint an administrator pastes into the directory (specs/088 R9). Null where the bucket has no SCIM
 * address to give — the administrators' bucket, or one with no address yet.
 */

export interface DirectoryGuidance {
	id: KnownDirectoryKey;
	displayName: string;
	recommendedCredential: DirectoryCredentialKind;
	fallbackCredential?: DirectoryCredentialKind;
	recommendedCorrelation: {
		claim: string;
		attribute: 'externalId' | 'userName';
	};
	labels: DirectoryLabels;
	steps: string[];
	pitfalls: string[];
	values: { scimBaseUrl: string | null; tokenEndpoint: string | null };
}

export function directoryGuidance(bucket: UserBucket): DirectoryGuidance[] {
	const base = scimBaseUrl(bucket);
	const values = {
		scimBaseUrl: base,
		tokenEndpoint: base === null ? null : tokenEndpointFor(bucket)
	};
	return KNOWN_DIRECTORIES.map((entry) => ({
		id: entry.id,
		displayName: entry.displayName,
		recommendedCredential: entry.recommendedCredential,
		...(entry.fallbackCredential
			? { fallbackCredential: entry.fallbackCredential }
			: {}),
		recommendedCorrelation: { ...entry.recommendedCorrelation },
		labels: { ...entry.labels },
		steps: [...entry.steps],
		pitfalls: [...entry.pitfalls],
		values
	}));
}
