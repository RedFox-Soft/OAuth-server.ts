import type { OIDCContext } from 'lib/helpers/oidc_context.ts';

interface JarParameters {
	request?: string;
	client_id?: string;
	[key: string]: unknown;
}

/*
 * Makes sure that
 * - unauthenticated clients send the JAR Request Object
 * - either JAR or plain request is provided
 * - request_uri is not used
 */
export default function stripOutsideJarParams(
	oidc: OIDCContext<JarParameters>
) {
	const { request, client_id } = oidc.params;
	const JAR = !!request;

	if (JAR) {
		oidc.params = { request, client_id };
	}
}
