// Standard verification email. Deliberately plain, inline-styled, table-free HTML with a
// plaintext fallback so it renders across mail clients (the antd/React interaction pages
// are for browsers, not inboxes).

interface LinkParams {
	appName: string;
	verifyUrl: string;
}

interface CodeParams {
	appName: string;
	code: string;
}

function escapeHtml(value: string): string {
	return value
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;');
}

function shell(appName: string, bodyHtml: string): string {
	return [
		`<div style="font-family: Arial, Helvetica, sans-serif; max-width: 480px; margin: 0 auto; color: #1f1f1f;">`,
		`<h2 style="font-size: 20px;">Verify your email</h2>`,
		`<p>Thanks for registering with ${escapeHtml(appName)}. Please confirm this email address to activate your account.</p>`,
		bodyHtml,
		`<p style="color: #8c8c8c; font-size: 12px; margin-top: 24px;">If you did not create this account, you can safely ignore this email.</p>`,
		`</div>`
	].join('');
}

export function verificationLinkEmail(params: LinkParams): {
	subject: string;
	html: string;
	text: string;
} {
	const { appName, verifyUrl } = params;
	const html = shell(
		appName,
		[
			`<p style="text-align: center; margin: 28px 0;">`,
			`<a href="${escapeHtml(verifyUrl)}" style="background: #1677ff; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 6px; display: inline-block;">Verify email</a>`,
			`</p>`,
			`<p style="font-size: 12px; color: #8c8c8c;">Or paste this link into your browser:<br/>${escapeHtml(verifyUrl)}</p>`
		].join('')
	);
	const text = `Verify your email for ${appName}.\n\nOpen this link to confirm your address:\n${verifyUrl}\n\nIf you did not create this account, you can ignore this email.`;
	return { subject: `Verify your email for ${appName}`, html, text };
}

export function verificationCodeEmail(params: CodeParams): {
	subject: string;
	html: string;
	text: string;
} {
	const { appName, code } = params;
	const html = shell(
		appName,
		[
			`<p>Enter this verification code to confirm your address:</p>`,
			`<p style="text-align: center; margin: 24px 0;">`,
			`<span style="font-size: 32px; letter-spacing: 8px; font-weight: bold;">${escapeHtml(code)}</span>`,
			`</p>`,
			`<p style="font-size: 12px; color: #8c8c8c;">This code expires shortly. Do not share it with anyone.</p>`
		].join('')
	);
	const text = `Verify your email for ${appName}.\n\nYour verification code is: ${code}\n\nThis code expires shortly. If you did not create this account, you can ignore this email.`;
	return { subject: `Your ${appName} verification code`, html, text };
}
