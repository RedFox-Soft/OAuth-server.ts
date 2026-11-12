import { describe, expect, it } from 'bun:test';

import { configuration } from 'lib/configs/application.ts';
import { signInRequirementUnmet } from 'lib/resources/sign_in_requirement.ts';

const NOW = 1_800_000_000;
const HOUR = 3600;

/**
 * @proves An API's sign-in requirement is met only by a sign-in that had a code (when one is required) and is no older
 * than allowed (when an age is set): every other context, including an absent, unknown or provider one, misses the
 * code, and a missing or unreadable sign-in time is never recent, so no sign-in that does not meet it is ever answered
 * as meeting it.
 */
describe("whether a sign-in meets an API's requirement", () => {
	const contexts = [
		configuration.acrMap.multi_factor,
		configuration.acrMap.password,
		configuration.acrMap.federated,
		'urn:somewhere:else',
		undefined,
		null
	];
	const times = [
		undefined,
		null,
		Number.NaN,
		Number.POSITIVE_INFINITY,
		NOW - 60,
		NOW - HOUR,
		NOW - HOUR - 1,
		NOW - 30 * 86_400
	];

	it('is answered by every combination exactly as the rule says', () => {
		for (const code of [false, true]) {
			for (const maxAgeSeconds of [undefined, HOUR]) {
				for (const acr of contexts) {
					for (const authTime of times) {
						const unmet = signInRequirementUnmet(
							{ code, ...(maxAgeSeconds ? { maxAgeSeconds } : {}) },
							{ acr, authTime },
							NOW
						);
						const missesCode =
							code && acr !== configuration.acrMap.multi_factor;
						const tooOld =
							maxAgeSeconds !== undefined &&
							!(
								typeof authTime === 'number' &&
								Number.isFinite(authTime) &&
								NOW - authTime <= maxAgeSeconds
							);

						expect({ code, maxAgeSeconds, acr, authTime, unmet }).toEqual({
							code,
							maxAgeSeconds,
							acr,
							authTime,
							unmet:
								missesCode || tooOld
									? { code: missesCode, recent: tooOld }
									: null
						});
					}
				}
			}
		}
	});

	it('asks nothing of an API with no requirement', () => {
		expect(
			signInRequirementUnmet(
				undefined,
				{ acr: undefined, authTime: undefined },
				NOW
			)
		).toBeNull();
	});
});
