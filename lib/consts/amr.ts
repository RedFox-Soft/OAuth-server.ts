import type { AcrDistinction } from './acr.ts';

/*
 * The Authentication Methods References this server reports, keyed by the way a person signed in, beside the
 * authentication context distinction that way reports. Both claims are read from one row of one table, so the
 * invariant holds by construction: a sign-in reports the multi-factor context only with a method that holds two
 * factors, and its `amr` names that method — never a password and a code it did not ask for (specs/139 research
 * R11). A passkey is the second such method: possession of a key (`pop`) and the device's own check of the person
 * (`user`), and a key the browser binds to the real site, so it reaches the phishing-resistant context (specs/142),
 * which meets every requirement of a code (lib/consts/acr.ts SATISFIED_BY). An application is told the multi-factor
 * context unless it asked for the phishing-resistant one (lib/helpers/acr_satisfaction.ts reportedAcr).
 *
 * The values are fixed, unlike the `acr` names an operator assigns: these are identifiers registered by RFC 8176 that
 * every relying party library already knows, and a renamed one would only be less understood. `mfa` sits beside the
 * individual methods, as RFC 8176 §2 allows and nearly every provider does, so a relying party can test for it
 * without knowing which factors this server has.
 *
 * A conditional passkey (specs/141 research R2), made after a password alone and not yet confirmed, is no more than
 * that password: it reports the password context, so every requirement of a code still asks for one, and its own
 * methods (`pop`, `user`) without `mfa`, since `pwd` would be untrue and would make it count as a fresh password.
 * Followed by a code, it is two factors like a password and a code, with the methods it actually used.
 *
 * A federated sign-in carries none. This server accepted another provider's assertion and observed no method of its
 * own; the provider's own `amr` is not forwarded, because vouching for it is an operator's decision per provider that
 * no setting expresses yet.
 *
 * The order is fixed so tokens are reproducible. It carries no meaning, and neither OIDC Core nor RFC 8176 gives it
 * one.
 *
 * Import-free on purpose, like acr.ts: it is read by the interaction producers and by tests, and must not drag an
 * adapter into either graph.
 */
export type AmrValue = 'pwd' | 'otp' | 'mfa' | 'pop' | 'user';

export const SIGN_IN_METHODS = [
	'password',
	'password_code',
	'passkey',
	'passkey_conditional',
	'passkey_conditional_code',
	'federated'
] as const;

export type SignInMethod = (typeof SIGN_IN_METHODS)[number];

export const AMR_FOR_METHOD: Record<SignInMethod, readonly AmrValue[]> = {
	password: ['pwd'],
	password_code: ['pwd', 'otp', 'mfa'],
	passkey: ['pop', 'user', 'mfa'],
	passkey_conditional: ['pop', 'user'],
	passkey_conditional_code: ['pop', 'user', 'otp', 'mfa'],
	federated: []
};

/* The context each way of signing in reports; the operator names it (`configuration.acrMap`). */
export const DISTINCTION_FOR_METHOD: Record<SignInMethod, AcrDistinction> = {
	password: 'password',
	password_code: 'multi_factor',
	passkey: 'phishing_resistant',
	passkey_conditional: 'password',
	passkey_conditional_code: 'multi_factor',
	federated: 'federated'
};
