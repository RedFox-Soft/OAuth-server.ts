import { describe, expect, it } from 'bun:test';

import { configuration } from 'lib/configs/application.ts';
import { signInRequirementUnmet } from 'lib/resources/sign_in_requirement.ts';
import { requirementUnmet } from 'lib/resources/sign_in_rule.ts';

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
		configuration.acrMap.phishing_resistant,
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
		for (const level of ['none', 'code', 'passkey'] as const) {
			const passkey = level === 'passkey';
			const code = level === 'code';
			for (const maxAgeSeconds of [undefined, HOUR]) {
				for (const acr of contexts) {
					for (const authTime of times) {
						const unmet = signInRequirementUnmet(
							{ passkey, code, ...(maxAgeSeconds ? { maxAgeSeconds } : {}) },
							{ acr, authTime },
							NOW
						);
						const withPasskey = acr === configuration.acrMap.phishing_resistant;
						const withCode =
							withPasskey || acr === configuration.acrMap.multi_factor;
						const missesPasskey = passkey && !withPasskey;
						const missesCode = !missesPasskey && code && !withCode;
						const tooOld =
							maxAgeSeconds !== undefined &&
							!(
								typeof authTime === 'number' &&
								Number.isFinite(authTime) &&
								NOW - authTime <= maxAgeSeconds
							);

						expect({
							passkey,
							code,
							maxAgeSeconds,
							acr,
							authTime,
							unmet
						}).toEqual({
							passkey,
							code,
							maxAgeSeconds,
							acr,
							authTime,
							unmet:
								missesPasskey || missesCode || tooOld
									? { passkey: missesPasskey, code: missesCode, recent: tooOld }
									: null
						});
					}
				}
			}
		}
	});

	it('is answered the same by the rule the console bundles, given whether the sign-in had a code or passkey', () => {
		for (const level of ['none', 'code', 'passkey'] as const) {
			const passkey = level === 'passkey';
			const code = level === 'code';
			for (const maxAgeSeconds of [undefined, HOUR]) {
				for (const acr of contexts) {
					for (const authTime of times) {
						const signIn = {
							passkey,
							code,
							...(maxAgeSeconds ? { maxAgeSeconds } : {})
						};
						const withPasskey = acr === configuration.acrMap.phishing_resistant;

						expect(
							requirementUnmet(
								signIn,
								{
									withPasskey,
									withCode:
										withPasskey || acr === configuration.acrMap.multi_factor,
									authTime
								},
								NOW
							)
						).toEqual(signInRequirementUnmet(signIn, { acr, authTime }, NOW));
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
