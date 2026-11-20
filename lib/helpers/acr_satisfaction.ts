import { configuration } from '../configs/application.ts';
import {
	ACR_DISTINCTIONS,
	SATISFIED_BY,
	type AcrDistinction
} from '../consts/acr.ts';

/*
 * The one place an authentication context is compared with another (specs/142 research R1). An operator names the
 * contexts and the server owns which meets which (`SATISFIED_BY`), so a comparison is always: turn the names back into
 * distinctions, then read the table. Nothing compares positions in a list: that would rank a provider sign-in above a
 * code, the mistake `11-critique-security` S8 describes.
 *
 * Two values travel with every token artefact (research R2). `acr` is what the application is told; `signInAcr` is what
 * the sign-in reached. Every requirement reads the second, through `reachedAcr`, so a record from before the split, or a
 * copy that forgot the field, is judged on the reported value, which is never stronger: it fails closed.
 */

/* The distinction an operator's name stands for; undefined for a name this server does not use. */
export function distinctionOf(
	value: string | null | undefined
): AcrDistinction | undefined {
	if (typeof value !== 'string') return undefined;
	const { acrMap } = configuration;
	return ACR_DISTINCTIONS.find((distinction) => acrMap[distinction] === value);
}

/* Whether a sign-in that reached `value` meets the `required` context. An unknown value meets nothing. */
export function meets(
	value: string | null | undefined,
	required: AcrDistinction
): boolean {
	const reached = distinctionOf(value);
	return reached !== undefined && SATISFIED_BY[required].includes(reached);
}

/* Whether it meets any of the requested names; a name this server does not use is never met. */
export function satisfiesAny(
	requested: readonly string[],
	value: string | null | undefined
): boolean {
	return requested.some((name) => {
		const required = distinctionOf(name);
		return required !== undefined && meets(value, required);
	});
}

/*
 * The strongest requested name the sign-in meets, or undefined. One context is stronger than another when meeting it
 * implies meeting the other, which the table says without a separate ranking: the fewer contexts satisfy a requirement,
 * the stronger it is. Names the sign-in meets all lie on one chain, so this never compares a provider sign-in with
 * anything else; equal strength keeps the request's order.
 */
export function strongestMet(
	requested: readonly string[],
	value: string | null | undefined
): string | undefined {
	let best: { name: string; breadth: number } | undefined;
	for (const name of requested) {
		const required = distinctionOf(name);
		if (required === undefined || !meets(value, required)) continue;
		const breadth = SATISFIED_BY[required].length;
		if (best === undefined || breadth < best.breadth) best = { name, breadth };
	}
	return best?.name;
}

/*
 * A phishing-resistant context lowered to the multi-factor one: what a sign-in reports when nobody asked for more, and
 * all a sign-in can reach when the browser that did the ceremony is not the one receiving the tokens (a device code, a
 * back-channel request: research R4, `11-critique-security` S11).
 */
export function capForOtherBrowser(value: string): string;
export function capForOtherBrowser(
	value: string | undefined
): string | undefined;
export function capForOtherBrowser(
	value: string | undefined
): string | undefined {
	return distinctionOf(value) === 'phishing_resistant'
		? configuration.acrMap.multi_factor
		: value;
}

interface AcrClaimRequest {
	value?: unknown;
	values?: unknown;
}

/*
 * The names a request asked for: its individual `acr` claim request, where `acr_values` and a client's
 * `default_acr_values` also arrive when no claim request exists (lib/actions/authorization/assign_claims.ts), so one
 * source carries both forms with the precedence the server already gives them.
 */
export function requestedAcrNames(claims: unknown): string[] {
	const request = (
		claims as { id_token?: { acr?: AcrClaimRequest | null } } | undefined
	)?.id_token?.acr;
	if (request === null || typeof request !== 'object') return [];
	if (Array.isArray(request.values)) {
		return request.values.filter(
			(value): value is string => typeof value === 'string'
		);
	}
	return typeof request.value === 'string' ? [request.value] : [];
}

/*
 * What a token says (Clarifications 2026-11-20, research R3): the strongest requested name the sign-in meets; with
 * none named, or none met, the context it reached, a phishing-resistant one reported as multi-factor. So `phr` reaches
 * only an application that asked for it, and one that asked for a weaker context receives exactly what it asked for.
 * Keycloak's `AcrUtils.mapLoaToAcr` answers the same way.
 */
export function reportedAcr(
	reached: string | undefined,
	claims: unknown
): string | undefined {
	if (reached === undefined) return undefined;
	return (
		strongestMet(requestedAcrNames(claims), reached) ??
		capForOtherBrowser(reached)
	);
}

/* The context the sign-in behind an artefact reached: `signInAcr`, or `acr` on a record from before the two were split. */
export function reachedAcr(payload: {
	readonly acr?: string | null;
	readonly signInAcr?: string | null;
}): string | undefined {
	return payload.signInAcr ?? payload.acr ?? undefined;
}
