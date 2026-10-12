// An administrator's invitation for a person to set their own password (specs/089). Same plain, inline-styled,
// table-free shape as the reset template, because it has to render in a mail client, not a browser.
//
// Distinct from the reset message on purpose: the person did not ask for anything, so a message saying "we
// received a request to reset your password" would read as somebody else's request — the confusion inviting
// people through "forgot password" caused. It names the bucket, says what the link does and how long it works,
// and carries no password, no account id and no bucket id: forwarded, it hands over the link and nothing else.

interface UserInvitationParams {
	bucketName: string;
	url: string;
}

function escapeHtml(value: string): string {
	return value
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;');
}

export function userInvitationEmail(params: UserInvitationParams): {
	subject: string;
	html: string;
	text: string;
} {
	const { bucketName, url } = params;
	const safeUrl = escapeHtml(url);
	const safeBucket = escapeHtml(bucketName);
	const html = [
		`<div style="font-family: Arial, Helvetica, sans-serif; max-width: 480px; margin: 0 auto; color: #1f1f1f;">`,
		`<h2 style="font-size: 20px;">You're invited to ${safeBucket}</h2>`,
		`<p>An administrator created an account for you at ${safeBucket}. Choose a password to start signing in.</p>`,
		`<p style="text-align: center; margin: 28px 0;">`,
		`<a href="${safeUrl}" style="background: #1677ff; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 6px; display: inline-block;">Set your password</a>`,
		`</p>`,
		`<p style="font-size: 12px; color: #8c8c8c;">Or paste this link into your browser:<br/>${safeUrl}</p>`,
		`<p style="font-size: 12px; color: #8c8c8c;">The link works for 7 days and can be used once. Setting a password also confirms this email address.</p>`,
		`<p style="color: #8c8c8c; font-size: 12px; margin-top: 24px;">If you were not expecting this, you can ignore this email — nothing happens until a password is chosen.</p>`,
		`</div>`
	].join('');
	const text = `You're invited to ${bucketName}.\n\nAn administrator created an account for you. Open this link to choose your password:\n${url}\n\nThe link works for 7 days and can be used once. Setting a password also confirms this email address.\n\nIf you were not expecting this, you can ignore this email — nothing happens until a password is chosen.`;
	return { subject: `Set your password for ${bucketName}`, html, text };
}
