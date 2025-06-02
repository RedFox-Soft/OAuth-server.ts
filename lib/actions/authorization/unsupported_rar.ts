import { InvalidRequest } from '../../helpers/errors.ts';

export default function unsupportedRar(ctx) {
	if (ctx.oidc.params.authorization_details !== undefined) {
		throw new InvalidRequest(
			`authorization_details is unsupported at the ${ctx.oidc.route}_endpoint`
		);
	}
}
