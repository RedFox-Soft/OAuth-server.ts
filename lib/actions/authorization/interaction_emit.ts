import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
import { eventBus } from '../../event_bus.js';

const resumeRoutes = new Set(['resume', 'device_resume']);

export default function interactionEmit(
	oidc: OIDCContext<PipelineParams>,
	next
) {
	if (resumeRoutes.has(oidc.route)) {
		eventBus.emit('interaction.ended', oidc);
	}

	return next();
}
