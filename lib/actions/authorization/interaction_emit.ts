const resumeRoutes = new Set(['resume', 'device_resume']);

export default function interactionEmit(oidc, next) {
	if (resumeRoutes.has(oidc.route)) {
		oidc.provider.emit('interaction.ended', oidc);
	}

	return next();
}
