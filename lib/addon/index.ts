import * as accountMod from './account.js';
import * as cibaMod from './ciba.js';
import * as claimsMod from './claims.js';
import * as corsMod from './cors.js';
import * as defaultMod from './default.js';
import * as interactionsMod from './interactions.js';
import * as introspectionMod from './introspection.js';
import * as mtlsMod from './mtls.js';
import * as rarMod from './rar.js';
import * as resourcesMod from './resources.js';
import * as tokensMod from './tokens.js';
import { resolve } from './registry.js';

export { shouldChange, mustChange } from './_warn.js';
export { addons } from './registry.js';
export type { AddonImplementations } from './types.js';

// Single import seam for the server's overridable behavior functions. Each
// accessor resolves its implementation through the override registry at call
// time (falling back to the addon-module default), so an override registered at
// any point — deployment bootstrap or a test's setup — takes effect regardless
// of module load order. Source modules import these accessors; they never read
// the functions off the merged configuration.
export const assertJwtClientAuthClaimsAndHeader: typeof defaultMod.assertJwtClientAuthClaimsAndHeader =
	(...args) =>
		resolve(
			'assertJwtClientAuthClaimsAndHeader',
			defaultMod.assertJwtClientAuthClaimsAndHeader
		)(...args);
export const clientBasedCORS: typeof corsMod.clientBasedCORS = (...args) =>
	resolve('clientBasedCORS', corsMod.clientBasedCORS)(...args);
export const loadExistingGrant: typeof accountMod.loadExistingGrant = (
	...args
) => resolve('loadExistingGrant', accountMod.loadExistingGrant)(...args);
export const findAccount: typeof accountMod.findAccount = (...args) =>
	resolve('findAccount', accountMod.findAccount)(...args);
export const expiresWithSession: typeof tokensMod.expiresWithSession = (
	...args
) => resolve('expiresWithSession', tokensMod.expiresWithSession)(...args);
export const issueRefreshToken: typeof tokensMod.issueRefreshToken = (
	...args
) => resolve('issueRefreshToken', tokensMod.issueRefreshToken)(...args);
export const pairwiseIdentifier: typeof tokensMod.pairwiseIdentifier = (
	...args
) => resolve('pairwiseIdentifier', tokensMod.pairwiseIdentifier)(...args);
export const rotateRefreshToken: typeof tokensMod.rotateRefreshToken = (
	...args
) => resolve('rotateRefreshToken', tokensMod.rotateRefreshToken)(...args);
export const idFactory: typeof tokensMod.idFactory = (...args) =>
	resolve('idFactory', tokensMod.idFactory)(...args);
export const secretFactory: typeof tokensMod.secretFactory = (...args) =>
	resolve('secretFactory', tokensMod.secretFactory)(...args);
export const defaultResource: typeof resourcesMod.defaultResource = (...args) =>
	resolve('defaultResource', resourcesMod.defaultResource)(...args);
export const useGrantedResource: typeof resourcesMod.useGrantedResource = (
	...args
) => resolve('useGrantedResource', resourcesMod.useGrantedResource)(...args);
export const getResourceServerInfo: typeof resourcesMod.getResourceServerInfo =
	(...args) =>
		resolve(
			'getResourceServerInfo',
			resourcesMod.getResourceServerInfo
		)(...args);
export const sectorIdentifierUriValidate: typeof claimsMod.sectorIdentifierUriValidate =
	(...args) =>
		resolve(
			'sectorIdentifierUriValidate',
			claimsMod.sectorIdentifierUriValidate
		)(...args);
export const assertClaimsParameter: typeof claimsMod.assertClaimsParameter = (
	...args
) => resolve('assertClaimsParameter', claimsMod.assertClaimsParameter)(...args);
export const assertJwtClaimsAndHeader: typeof claimsMod.assertJwtClaimsAndHeader =
	(...args) =>
		resolve(
			'assertJwtClaimsAndHeader',
			claimsMod.assertJwtClaimsAndHeader
		)(...args);
export const deviceInfo: typeof interactionsMod.deviceInfo = (...args) =>
	resolve('deviceInfo', interactionsMod.deviceInfo)(...args);
export const interactionPolicy: typeof interactionsMod.interactionPolicy = (
	...args
) => resolve('interactionPolicy', interactionsMod.interactionPolicy)(...args);
// Not wrapped in resolve(): both already read through the override registry internally.
export { interactionPolicyControl, supportedPrompts } from './interactions.js';
export const introspectionAllowedPolicy: typeof introspectionMod.introspectionAllowedPolicy =
	(...args) =>
		resolve(
			'introspectionAllowedPolicy',
			introspectionMod.introspectionAllowedPolicy
		)(...args);
export const getCertificate: typeof mtlsMod.getCertificate = (...args) =>
	resolve('getCertificate', mtlsMod.getCertificate)(...args);
export const certificateAuthorized: typeof mtlsMod.certificateAuthorized = (
	...args
) => resolve('certificateAuthorized', mtlsMod.certificateAuthorized)(...args);
export const certificateSubjectMatches: typeof mtlsMod.certificateSubjectMatches =
	(...args) =>
		resolve(
			'certificateSubjectMatches',
			mtlsMod.certificateSubjectMatches
		)(...args);
export const triggerAuthenticationDevice: typeof cibaMod.triggerAuthenticationDevice =
	(...args) =>
		resolve(
			'triggerAuthenticationDevice',
			cibaMod.triggerAuthenticationDevice
		)(...args);
export const validateBindingMessage: typeof cibaMod.validateBindingMessage = (
	...args
) => resolve('validateBindingMessage', cibaMod.validateBindingMessage)(...args);
export const validateRequestContext: typeof cibaMod.validateRequestContext = (
	...args
) => resolve('validateRequestContext', cibaMod.validateRequestContext)(...args);
export const processLoginHintToken: typeof cibaMod.processLoginHintToken = (
	...args
) => resolve('processLoginHintToken', cibaMod.processLoginHintToken)(...args);
export const processLoginHint: typeof cibaMod.processLoginHint = (...args) =>
	resolve('processLoginHint', cibaMod.processLoginHint)(...args);
export const verifyUserCode: typeof cibaMod.verifyUserCode = (...args) =>
	resolve('verifyUserCode', cibaMod.verifyUserCode)(...args);
export const rarForAuthorizationCode: typeof rarMod.rarForAuthorizationCode = (
	...args
) =>
	resolve('rarForAuthorizationCode', rarMod.rarForAuthorizationCode)(...args);
export const rarForCodeResponse: typeof rarMod.rarForCodeResponse = (...args) =>
	resolve('rarForCodeResponse', rarMod.rarForCodeResponse)(...args);
export const rarForRefreshTokenResponse: typeof rarMod.rarForRefreshTokenResponse =
	(...args) =>
		resolve(
			'rarForRefreshTokenResponse',
			rarMod.rarForRefreshTokenResponse
		)(...args);
export const rarForIntrospectionResponse: typeof rarMod.rarForIntrospectionResponse =
	(...args) =>
		resolve(
			'rarForIntrospectionResponse',
			rarMod.rarForIntrospectionResponse
		)(...args);
