import type { AddonImplementations } from './types.js';

/*
 * The seam names as data. AddonImplementations is a type and vanishes at runtime, and the index's
 * accessors are the seams only by convention — so a documentation export, or anything else that needs
 * to enumerate "what can a deployment override", has nowhere else to read the list from.
 *
 * Type-only import, deliberately: this module must stay loadable without the model graph, like
 * registry.ts. The `satisfies` clause rejects a name that is not a seam; the `Missing` check below
 * rejects a seam that is not named, so the list cannot fall behind the interface silently.
 */
export const ADDON_SEAMS = [
	'assertJwtClientAuthClaimsAndHeader',
	'loadExistingGrant',
	'findAccount',
	'expiresWithSession',
	'issueRefreshToken',
	'pairwiseIdentifier',
	'rotateRefreshToken',
	'idFactory',
	'secretFactory',
	'defaultResource',
	'useGrantedResource',
	'getResourceServerInfo',
	'sectorIdentifierUriValidate',
	'assertClaimsParameter',
	'assertJwtClaimsAndHeader',
	'deviceInfo',
	'interactionPolicy',
	'introspectionAllowedPolicy',
	'getCertificate',
	'certificateAuthorized',
	'certificateSubjectMatches',
	'triggerAuthenticationDevice',
	'validateBindingMessage',
	'validateRequestContext',
	'processLoginHintToken',
	'processLoginHint',
	'verifyUserCode',
	'rarForAuthorizationCode',
	'rarForCodeResponse',
	'rarForRefreshTokenResponse',
	'rarForIntrospectionResponse'
] as const satisfies readonly (keyof AddonImplementations)[];

type Missing = Exclude<
	keyof AddonImplementations,
	(typeof ADDON_SEAMS)[number]
>;
// Fails to compile when AddonImplementations gains a key the list above does not name.
const _everySeamIsListed: [Missing] extends [never] ? true : never = true;
void _everySeamIsListed;
