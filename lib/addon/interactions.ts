export function deviceInfo(ctx) {
	return {
		ip: ctx.ip,
		ua: ctx.get('user-agent')
	};
}
