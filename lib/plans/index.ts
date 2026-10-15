/*
 * Plans and Free-tier limits (specs/102). Split so the end-user paths (interactions, federation) import only
 * catalogue and sign-up reads, never the admin error type the enforcement module throws.
 */
export {
	catalogue,
	defaultOf,
	defaultPlan,
	planOf,
	plansEnabled
} from './catalogue.js';
export { signUpsPaused, forgetSignUpReadings } from './signups.js';
export { classifyProvider, type ProviderInput } from './provider.js';
export { bucketClients, bucketUsage, holdingsOf } from './usage.js';
