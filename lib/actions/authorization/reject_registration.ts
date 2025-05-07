import { RegistrationNotSupported } from '../../helpers/errors.ts';

/*
 * Rejects registration parameter as not supported.
 */
export default function rejectRegistration(ctx) {
	if (ctx.oidc.params.registration !== undefined) {
		throw new RegistrationNotSupported();
	}
}
