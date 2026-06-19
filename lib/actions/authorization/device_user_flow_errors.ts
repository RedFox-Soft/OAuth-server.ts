import { AccessDenied } from '../../helpers/errors.ts';
import errOut from '../../helpers/err_out.ts';
import { ReRenderError, AbortedError } from '../../helpers/re_render_errors.ts';
import { DeviceCode } from 'lib/models/device_code.js';

export default async function deviceUserFlowErrors(oidc, next) {
	try {
		await next();
	} catch (err) {
		if (!(err instanceof ReRenderError)) {
			const out = errOut(err);

			let code = oidc.deviceCode;

			if (!code && oidc.entities.Interaction?.deviceCode) {
				code = await DeviceCode.find(oidc.entities.Interaction.deviceCode, {
					ignoreExpiration: true,
					ignoreSessionBinding: true
				});
			}

			if (code) {
				Object.assign(code, {
					error: out.error,
					errorDescription: out.error_description
				});
				await code.save();
				if (err instanceof AccessDenied) {
					throw new AbortedError();
				}
			}
		}

		throw err;
	}
}
