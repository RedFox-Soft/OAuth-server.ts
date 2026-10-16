// The message a super administrator sends themselves from the mail settings, to learn whether this server
// can deliver mail at all. Its arrival is the whole answer, so it says only that, which server sent it, and
// that the real messages go the same way. English only, like every administrator's mail.

interface SmtpTestParams {
	issuer: string;
}

function escapeHtml(value: string): string {
	return value
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;');
}

export function smtpTestEmail(params: SmtpTestParams): {
	subject: string;
	html: string;
	text: string;
} {
	const what = `This is a test message from the server at ${params.issuer}.`;
	const meaning =
		'It arrived, so outgoing mail works: verification, password reset and invitation messages are delivered the same way. If it landed in spam, check the SPF, DKIM and DMARC records of the sender’s domain.';

	const html = [
		`<div style="font-family: Arial, Helvetica, sans-serif; max-width: 480px; margin: 0 auto; color: #1f1f1f;">`,
		`<h2 style="font-size: 20px;">Mail delivery works</h2>`,
		`<p>${escapeHtml(what)}</p>`,
		`<p>${escapeHtml(meaning)}</p>`,
		`</div>`
	].join('');

	return {
		subject: 'Test message: mail delivery works',
		html,
		text: `${what}\n\n${meaning}`
	};
}
