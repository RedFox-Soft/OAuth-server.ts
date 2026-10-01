import type { AcrDistinction } from './acr.ts';

/*
 * The Authentication Methods References this server reports, keyed by the authentication context
 * distinction each sign-in already decides. One decision yields both claims, so a sign-in can never
 * report the multi-factor context with a password-only `amr`, or the reverse.
 *
 * The values are fixed, unlike the `acr` names an operator assigns: these are identifiers registered
 * by RFC 8176 that every relying party library already knows, and a renamed one would only be less
 * understood. `mfa` sits beside the individual methods, as RFC 8176 §2 allows and nearly every
 * provider does, so a relying party can test for it without knowing which factors this server has.
 *
 * A federated sign-in carries none. This server accepted another provider's assertion and observed
 * no method of its own; the provider's own `amr` is not forwarded, because vouching for it is an
 * operator's decision per provider that no setting expresses yet.
 *
 * The order is fixed so tokens are reproducible. It carries no meaning, and neither OIDC Core nor
 * RFC 8176 gives it one.
 *
 * Import-free on purpose, like acr.ts: it is read by the interaction producers and by tests, and
 * must not drag an adapter into either graph.
 */
export type AmrValue = 'pwd' | 'otp' | 'mfa';

export const AMR_FOR_DISTINCTION: Record<AcrDistinction, readonly AmrValue[]> =
	{
		password: ['pwd'],
		multi_factor: ['pwd', 'otp', 'mfa'],
		federated: []
	};
