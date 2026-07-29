import { eventBus } from '../../event_bus.js';

const resumeRoutes = new Set(['resume', 'device_resume']);

export default function interactionEmit(oidc, next) {
	if (resumeRoutes.has(oidc.route)) {
		eventBus.emit('interaction.ended', oidc);
	}

	return next();
}
