// Standard password-reset email. Deliberately plain, inline-styled, table-free HTML with a plaintext
// fallback so it renders across mail clients (the antd/React interaction pages are for browsers, not
// inboxes) — the same shape templates/verification.ts uses.
//
// Carries the link and nothing else about the account: no password, no hash, no account id, no bucket id.
// A forwarded reset email should hand the recipient the ability to set a password and no other knowledge.

interface ResetParams {
	appName: string;
	resetUrl: string;
}

function escapeHtml(value: string): string {
	return value
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;');
}

export function passwordResetEmail(params: ResetParams): {
	subject: string;
	html: string;
	text: string;
} {
	const { appName, resetUrl } = params;
	const safeUrl = escapeHtml(resetUrl);
	const html = [
		`<div style="font-family: Arial, Helvetica, sans-serif; max-width: 480px; margin: 0 auto; color: #1f1f1f;">`,
		`<h2 style="font-size: 20px;">Reset your password</h2>`,
		`<p>We received a request to set a new password for your ${escapeHtml(appName)} account.</p>`,
		`<p style="text-align: center; margin: 28px 0;">`,
		`<a href="${safeUrl}" style="background: #1677ff; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 6px; display: inline-block;">Choose a new password</a>`,
		`</p>`,
		`<p style="font-size: 12px; color: #8c8c8c;">Or paste this link into your browser:<br/>${safeUrl}</p>`,
		`<p style="font-size: 12px; color: #8c8c8c;">This link expires in one hour and can be used once.</p>`,
		// The line that matters when the request was not the account holder's: doing nothing leaves the
		// existing password working, so there is no action to take and nothing to worry about.
		`<p style="color: #8c8c8c; font-size: 12px; margin-top: 24px;">If you did not ask to reset your password, you can safely ignore this email — your current password still works.</p>`,
		`</div>`
	].join('');
	const text = `Reset your password for ${appName}.\n\nOpen this link to choose a new password:\n${resetUrl}\n\nThis link expires in one hour and can be used once.\n\nIf you did not ask to reset your password, you can ignore this email — your current password still works.`;
	return { subject: `Reset your password for ${appName}`, html, text };
}
