const issuer = process.env.ISSUER;
if (!issuer) {
	throw new Error('ISSUER environment variable is not set');
}

export const ISSUER = issuer;
