// A provisioning connection's mass-deprovisioning guard has held it. The first mail this server sends to its
// administrators about something it did rather than something they asked for, in the same plain,
// inline-styled, table-free shape as the other templates, because it has to render in a mail client.
//
// Names the connection, the bucket, when and after how many deprovisionings, and where to go. Nothing about
// the people the directory tried to deprovision: a mail is forwarded and kept, and who was about to lose
// access is for the console, behind the administrator's sign-in.

interface DeprovisioningHeldParams {
	connectionName: string;
	bucketName: string;
	since: Date;
	count: number;
	consoleUrl: string;
}

function escapeHtml(value: string): string {
	return value
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;');
}

export function deprovisioningHeldEmail(params: DeprovisioningHeldParams): {
	subject: string;
	html: string;
	text: string;
} {
	const { connectionName, bucketName, since, count, consoleUrl } = params;
	const when = since.toISOString();
	const safeConnection = escapeHtml(connectionName);
	const safeBucket = escapeHtml(bucketName);
	const safeUrl = escapeHtml(consoleUrl);
	const plural = count === 1 ? '' : 's';
	const what = `The provisioning connection "${connectionName}" of the user bucket "${bucketName}" reached its limit of ${count} deprovisioning${plural} and was held at ${when}.`;
	const consequence =
		'Until an administrator of the bucket releases it, every deactivation and deletion it sends is refused and retried later by the directory; creates and updates still go through. People the directory is removing keep their access meanwhile.';

	const html = [
		`<div style="font-family: Arial, Helvetica, sans-serif; max-width: 480px; margin: 0 auto; color: #1f1f1f;">`,
		`<h2 style="font-size: 20px;">Provisioning connection held</h2>`,
		`<p>The provisioning connection <strong>${safeConnection}</strong> of the user bucket <strong>${safeBucket}</strong> reached its limit of ${count} deprovisioning${plural} and was held at ${escapeHtml(when)}.</p>`,
		`<p>${escapeHtml(consequence)}</p>`,
		`<p>Check the directory for a mistaken rule before releasing the hold.</p>`,
		`<p style="text-align: center; margin: 28px 0;">`,
		`<a href="${safeUrl}" style="background: #1677ff; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 6px; display: inline-block;">Open the admin console</a>`,
		`</p>`,
		`<p style="font-size: 12px; color: #8c8c8c;">Or paste this link into your browser:<br/>${safeUrl}</p>`,
		`</div>`
	].join('');

	const text = `${what}\n\n${consequence}\n\nCheck the directory for a mistaken rule before releasing the hold:\n${consoleUrl}`;

	return {
		subject: `Provisioning connection "${connectionName}" held`,
		html,
		text
	};
}
