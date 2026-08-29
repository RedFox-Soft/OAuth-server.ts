// Invitation into an administrative group. Same plain, inline-styled, table-free shape as the
// password-reset and verification templates, for the same reason: it has to render in a mail client,
// not a browser.
//
// Carries the group's name, who invited them, and the link. Deliberately nothing else — not the
// group's id, not what it owns, not who else is in it. A forwarded invitation should hand the
// recipient the ability to accept and no knowledge of the tenant they have not joined yet.

interface InvitationParams {
	appName: string;
	groupName: string;
	invitedByEmail: string;
	acceptUrl: string;
	/* Whether accepting will create an account, which changes what the recipient is agreeing to. */
	createsAccount: boolean;
}

function escapeHtml(value: string): string {
	return value
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;');
}

export function groupInvitationEmail(params: InvitationParams): {
	subject: string;
	html: string;
	text: string;
} {
	const { appName, groupName, invitedByEmail, acceptUrl, createsAccount } =
		params;
	const safeUrl = escapeHtml(acceptUrl);
	const safeGroup = escapeHtml(groupName);
	const safeInviter = escapeHtml(invitedByEmail);
	const outcome = createsAccount
		? 'Accepting creates an administrator account for this address.'
		: 'Accepting adds your existing administrator account to the group.';

	const html = [
		`<div style="font-family: Arial, Helvetica, sans-serif; max-width: 480px; margin: 0 auto; color: #1f1f1f;">`,
		`<h2 style="font-size: 20px;">Join ${safeGroup}</h2>`,
		`<p>${safeInviter} invited you to administer ${safeGroup} on ${escapeHtml(appName)}.</p>`,
		`<p style="text-align: center; margin: 28px 0;">`,
		`<a href="${safeUrl}" style="background: #1677ff; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 6px; display: inline-block;">Accept the invitation</a>`,
		`</p>`,
		`<p style="font-size: 12px; color: #8c8c8c;">Or paste this link into your browser:<br/>${safeUrl}</p>`,
		`<p style="font-size: 12px; color: #8c8c8c;">${escapeHtml(outcome)} This link expires in seven days and can be used once.</p>`,
		// The line that matters when the invitation was not expected: ignoring it grants nothing, so
		// there is no action to take.
		`<p style="color: #8c8c8c; font-size: 12px; margin-top: 24px;">If you were not expecting this, you can safely ignore this email — nothing is shared with you unless you accept.</p>`,
		`</div>`
	].join('');

	const text = `${invitedByEmail} invited you to administer ${groupName} on ${appName}.\n\nOpen this link to accept:\n${acceptUrl}\n\n${outcome} This link expires in seven days and can be used once.\n\nIf you were not expecting this, you can ignore this email — nothing is shared with you unless you accept.`;

	return { subject: `Join ${groupName} on ${appName}`, html, text };
}
