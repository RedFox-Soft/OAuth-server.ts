/*
 * The admin API's per-origin limiter is off: several cases here send many requests from one origin on purpose —
 * invitations up to their bounds, keys up to theirs — and what they prove is the feature's own bound, not the
 * limiter's.
 */
export const ApplicationConfig = {
	'rateLimit.enabled': false,
	// So an application's back-channel logout address is kept, and its https rule can be seen.
	'backchannelLogout.enabled': true
};
