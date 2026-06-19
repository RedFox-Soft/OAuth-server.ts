import { InvalidRequest } from '../../helpers/errors.ts';

export default function unsupportedRar(oidc) {
	if (oidc.params.authorization_details !== undefined) {
		throw new InvalidRequest(
			`authorization_details is unsupported at the ${oidc.route}_endpoint`
		);
	}
}
